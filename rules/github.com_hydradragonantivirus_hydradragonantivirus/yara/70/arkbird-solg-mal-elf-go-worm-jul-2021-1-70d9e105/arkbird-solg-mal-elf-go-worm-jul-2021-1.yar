rule ARKBIRD_SOLG_MAL_ELF_Go_Worm_Jul_2021_1: FILE {
  meta:
    description = "Detect the worm written in Go that drops XMRig Miner"
    author      = "Arkbird_SOLG"
    id          = "6f4a9d3a-e038-5d7f-9c18-c380a0b295d2"
    date        = "2021-07-06"
    modified    = "2021-07-06"
    reference   = "https://twitter.com/JAMESWT_MHT/status/1409848815948111877"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-06/MAL_ELF_Go_Worm_Jul_2021_1.yara#L1-L22"
    license_url = "N/A"
    logic_hash  = "be8b95f8aab62d3a2b3376a0481ebc609afcd089e0613d39f258e07366b708a1"
    score       = 75
    quality     = 61
    tags        = "FILE"
    hash1       = "774ccd1281b02bc9f0c7e7185c424a42cd98bcc758c893e8a96dfb206a02fcbe"
    hash2       = "bea5a4358184555924ab6c831bf34edf279f4b93d750d5321263439dcf9c245a"
    tlp         = "White"
    adversary   = "-"

  strings:
    $s1 = "Worker: (%d), Check IP(%s) with SSH port is open..."
    $s2 = "cat /dev/null > ~/.bash_history && history -c"
    $s3 = "nohup ./%s &> mysqllogs &"
    $s4 = "rm -f %s mysqllogs"
    $s5 = "command -v bash"
    $s6 = "Stop brute on, Worker: (%d), Try: IP: %s, credential: %s/%s (%d/%d): DURATION: %f"
    $s7 = "Worker: (%d), Try: IP: %s, credential: %s/%s (%d/%d)"

  condition:
    uint32(0) == 0x464c457f and filesize > 900KB and all of ($s*)
}
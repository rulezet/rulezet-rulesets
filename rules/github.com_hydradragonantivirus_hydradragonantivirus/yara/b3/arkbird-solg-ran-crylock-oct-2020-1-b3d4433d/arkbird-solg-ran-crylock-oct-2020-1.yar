rule ARKBIRD_SOLG_RAN_Crylock_Oct_2020_1: FILE {
  meta:
    description = "Detect CryLock ransomware V2.0.0"
    author      = "Arkbird_SOLG"
    id          = "642211e0-b5fe-5842-ab16-ca1fc8d00ac0"
    date        = "2020-10-14"
    modified    = "2020-10-15"
    reference   = "https://twitter.com/JAMESWT_MHT/status/1316426560803680257"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-10-15/Crylock/RAN_CryLock_Oct_2020_1.yar#L1-L31"
    license_url = "N/A"
    logic_hash  = "5d9aae41283c5738f2e584ea8d236ae64f7615ec629f9513fddb611714ddc230"
    score       = 75
    quality     = 71
    tags        = "FILE"
    hash1       = "04d8109c6c78055d772c01fefe1e5f48a70f2a65535cff17227b5a2c8506b831"

  strings:
    $s1     = "All commands sended to execution" fullword ascii
    $s2     = "Processesblacklist1" fullword ascii
    $s3     = "Execute all" fullword ascii
    $s4     = "config.txt" fullword ascii
    $debug1 = "Processed files: " fullword ascii
    $debug2 = "Next -->" fullword ascii
    $debug3 = "Status: scan network" fullword ascii
    $debug4 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")"
    $debug5 = "JumpID(\"\",\"%s\")"
    $debug6 = { 45 6e 63 72 79 70 74 65 64 20 62 79 20 42 6c 61 63 6b 52 61 62 62 69 74 2e 20 28 [3-10] 29 }
    $ran1   = "w_to_decrypt.hta" wide
    $ran2   = "<%UNDECRYPT_DATETIME%>" fullword ascii
    $ran3   = "<%START_DATETIME%>" fullword ascii
    $ran4   = "<%MAIN_CONTACT%>" fullword ascii
    $ran5   = "<%RESERVE_CONTACT%>" fullword ascii
    $ran6   = "<%HID%>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize > 300KB and 3 of ($s*) and 4 of ($debug*) and 4 of ($ran*)
}
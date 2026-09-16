rule ARKBIRD_SOLG_APT_APT28_Zekapab_Mar_2021_1: FILE {
  meta:
    description = "Detect Zekapab used by APT28 group"
    author      = "Arkbird_SOLG"
    id          = "634f32dd-8bcf-5c58-a335-9b66ff568a54"
    date        = "2021-03-15"
    modified    = "2021-03-15"
    reference   = "https://twitter.com/DrunkBinary/status/1371423755608719360"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-15/APT28/APT_APT28_Zekapab_Mar_2021_1.yar#L1-L25"
    license_url = "N/A"
    logic_hash  = "dabaab47c193a05620d282a00b6b47f710cfa6b1efc699ea5d47267d10cfdcb6"
    score       = 60
    quality     = 23
    tags        = "FILE"
    hash1       = "eae62bb4110bcd00e9d1bcaba9000defcda3d1ab832fa2634d928559d066cb15"

  strings:
    $s1      = "http://"
    $s2      = "https://"
    $s3      = "2D4F70656E2070726F636573732D"
    $s4      = "5043204E616D653A20"
    $s5      = "4B427264204C616E673A20"
    $s6      = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
    $header1 = "--%s\r\nContent-Disposition: form-data; name=\"%s\""
    $header2 = "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s"
    $dbg1    = { 46 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 0d 00 4e 00 6f 00 74 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 }
    $dbg2    = { 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 45 00 72 00 72 00 6f 00 72 00 2e 00 20 00 20 00 43 00 6f 00 64 00 65 00 3a 00 20 00 25 00 64 00 2e 00 0d 00 0a 00 25 00 73 }
    $dbg3    = { 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 25 00 73 00 2e 00 0a 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 2e }
    $dbg4    = { 45 00 72 00 72 00 6f 00 72 00 20 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 20 00 25 00 73 00 25 00 73 00 25 00 73 00 3a 00 20 00 25 00 73 }
    $dbg5    = { 52 00 65 00 73 00 6f 00 6c 00 76 00 69 00 6e 00 67 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 20 00 25 00 73 00 2e }
    $dbg6    = { 53 00 6f 00 63 00 6b 00 65 00 74 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 23 00 20 00 25 00 64 00 0d 00 0a 00 25 00 73 }

  condition:
    uint16(0) == 0x5a4d and filesize > 100KB and 1 of ($header*) and 3 of ($s*) and 4 of ($dbg*)
}
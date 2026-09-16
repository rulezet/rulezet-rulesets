rule ARKBIRD_SOLG_MAL_Powerpool_Jul_2021_1: FILE {
  meta:
    description = "Detect PowerPool malware"
    author      = "Arkbird_SOLG"
    id          = "8248300e-fc3e-56df-be4a-f1850e2bedc8"
    date        = "2021-07-09"
    modified    = "2021-07-12"
    reference   = "https://securelist.com/iamtheking-and-the-slothfulmedia-malware-family/99000/"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-11/IAmTheKing/MAL_PowerPool_Jul_2021_1.yara#L1-L29"
    license_url = "N/A"
    logic_hash  = "0978a6cd60533ffda0c2b13ea98dc1ba46a464890b895cb2704804a763756fca"
    score       = 75
    quality     = 73
    tags        = "FILE"
    hash1       = "9c08136b26ee5234c61a5d9e5a17afb15da35efc66514d2df5b53178693644c5"
    hash2       = "23e7e0bbc36d523daa8e3cd8e32618c6c1fb61e32f664756e77d7917b3b11644"
    hash3       = "e30d32cc40ad19add7dfdcbed960d5f074ea632b796ae975b75eb25455b66bb0"
    hash4       = "88e7813340194acc4b094fd48ecf665a12d19245b90f2a69dab5861982ca95f6"
    tlp         = "White"
    adversary   = "IAmTheKing"

  strings:
    $s1 = "write info fail!!! GetLastError-->%u" fullword ascii
    $s2 = "Set Option failed errcode: %ld" fullword ascii
    $s3 = { 68 96 00 00 00 68 ?? c4 44 00 b9 ?? 4c 45 00 e8 [2] fb ff 68 [2] 44 00 e8 ?? 4f fe ff 59 c3 68 96 00 00 00 68 ?? c5 44 00 b9 ?? 4c 45 00 e8 [2] fb ff 68 [2] 44 00 e8 ?? 4f fe ff 59 c3 68 96 00 00 00 68 [2] 44 00 b9 ?? 4c 45 00 e8 [2] fb ff 68 [2] 44 00 e8 [2] fe ff 59 c3 83 3d ?? 4c 45 00 00 74 38 53 6a 01 b8 ?? 4c 45 00 e8 ?? a0 fc ff 50 6a 00 b9 ?? 4c 45 00 e8 [2] fb ff 6a ff bb 01 00 00 00 b8 ?? 4c 45 00 e8 [2] fc ff 40 50 b9 ?? 4c 45 00 e8 [2] fb ff 5b 33 c0 6a ff 50 68 ?? 4c 45 00 }
    $s4 = "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\""
    $s5 = "Content-Type: multipart/form-data; boundary=--MULTI-PARTS-FORM-DATA-BOUNDARY\r\n"
    $s6 = "Content-Disposition: form-data; name=\"%s\"\r\n\r\n"
    $s7 = "Content-Type: application/x-www-form-urlencoded\r\n"
    $s8 = "%s;type=%s;length=%s;realdata=%send"

  condition:
    uint16(0) == 0x5a4d and filesize > 100KB and 6 of ($s*)
}
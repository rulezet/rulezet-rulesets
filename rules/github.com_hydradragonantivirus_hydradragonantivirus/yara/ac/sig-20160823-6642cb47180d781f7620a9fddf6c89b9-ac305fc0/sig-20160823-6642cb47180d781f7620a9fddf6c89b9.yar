rule sig_20160823_6642cb47180d781f7620a9fddf6c89b9 {
  meta:
    description = "datamaliciousorder - file 20160823_6642cb47180d781f7620a9fddf6c89b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc7b2fd8dcd731d0749eb5fcbeb0e147d5f5320e273bf70fc55e95b0d5f9c4f"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
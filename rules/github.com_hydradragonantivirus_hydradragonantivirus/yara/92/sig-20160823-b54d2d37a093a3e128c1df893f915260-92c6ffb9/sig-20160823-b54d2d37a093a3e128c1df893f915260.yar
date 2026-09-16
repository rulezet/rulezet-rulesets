rule sig_20160823_b54d2d37a093a3e128c1df893f915260 {
  meta:
    description = "datamaliciousorder - file 20160823_b54d2d37a093a3e128c1df893f915260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9855218897729e797cef7185b07b97d19a8e6467f4d217496c5d767d25d1342"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
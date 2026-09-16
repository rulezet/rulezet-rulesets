rule sig_20160823_c950ead3e65e8218feb0afb57be3dc2b {
  meta:
    description = "datamaliciousorder - file 20160823_c950ead3e65e8218feb0afb57be3dc2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f555bcc7d40e01fddf327d43bbb668c312d6f88ad1ef93f3926cdbd99c41a85"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
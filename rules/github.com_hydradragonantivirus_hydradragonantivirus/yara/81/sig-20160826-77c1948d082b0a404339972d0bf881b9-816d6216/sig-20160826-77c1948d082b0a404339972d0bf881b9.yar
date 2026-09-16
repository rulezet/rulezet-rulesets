rule sig_20160826_77c1948d082b0a404339972d0bf881b9 {
  meta:
    description = "datamaliciousorder - file 20160826_77c1948d082b0a404339972d0bf881b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd05d796bcb11643333cbfa93470ace0d9bd33293fb15ebfb5c24e34a83c21a5"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}
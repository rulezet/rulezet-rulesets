rule sig_20160823_cbf8de68b3cb2acbdde0287b6d7aef5a {
  meta:
    description = "datamaliciousorder - file 20160823_cbf8de68b3cb2acbdde0287b6d7aef5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "182058d97162966decc784c399eea44ffa90be031a185ffaff2e183eb811fa90"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160822_3fd6f9aa08537d7736e22100a8be59fc {
  meta:
    description = "datamaliciousorder - file 20160822_3fd6f9aa08537d7736e22100a8be59fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617652ab4b765291283652c2e578ddf016a1ce860d8d8873ab151b1962d54d31"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160314_30d289ad8e52b08ee8c6a38279a7733b {
  meta:
    description = "datamaliciousorder - file 20160314_30d289ad8e52b08ee8c6a38279a7733b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2c18b88cf5178f14b219b82eb6cf8f5d1b88fed1b17cb41d1e865f2e703e09a"

  strings:
    $s1 = "kMjCCbEp.open(snPWcGSGJu + MZpJdIv, KziddNi + dGcIxhgQLc + iMdTblNHm + JddOwUhkwgvM + neYEjP + TTnzOFtShokimMk + CairXckKbdUHGF " ascii
    $s2 = "while (kMjCCbEp.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return rUepqpqCCtEnidP + TTNhFtsMe + XoVtSqbuB + jZXMZc + iNQBsU + kBuBo + IbdgryrwBWaChmJ" fullword ascii
    $s4 = "CM + meOjPkQbVwJmSR + nPSm + bLGSjfCTbOrp + qlQoVXz + sDaKwEsgcWcIyLg, false);" fullword ascii
    $s5 = "var UJQGcOJqeyYoR = new Date();" fullword ascii
    $s6 = "function DVjhHyqUVdRYE(fname)" fullword ascii
    $s7 = "function MHHLA(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
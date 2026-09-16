rule sig_20161024_c08ab2ffafa94fe4a91abaed67818ac0 {
  meta:
    description = "datamaliciousorder - file 20161024_c08ab2ffafa94fe4a91abaed67818ac0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf08f7c18f0353f89e7486f205a3d4621dacaf14a5b6402ec3432a985fd8626"

  strings:
    $s1 = "} while (th++ < np);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}
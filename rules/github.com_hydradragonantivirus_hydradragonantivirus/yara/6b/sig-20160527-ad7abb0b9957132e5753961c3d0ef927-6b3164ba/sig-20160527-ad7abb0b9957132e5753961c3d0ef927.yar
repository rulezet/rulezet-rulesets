rule sig_20160527_ad7abb0b9957132e5753961c3d0ef927 {
  meta:
    description = "datamaliciousorder - file 20160527_ad7abb0b9957132e5753961c3d0ef927.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8368d1a5c977dfff60aaa2096a793507ee80ef7cbb02edcfc958f926033ea91"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a740wSoqk.length;i++)if(i%2==0)x.push(a740wSoqk[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
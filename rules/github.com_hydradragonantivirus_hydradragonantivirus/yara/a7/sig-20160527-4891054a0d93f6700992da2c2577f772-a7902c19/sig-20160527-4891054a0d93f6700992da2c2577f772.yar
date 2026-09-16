rule sig_20160527_4891054a0d93f6700992da2c2577f772 {
  meta:
    description = "datamaliciousorder - file 20160527_4891054a0d93f6700992da2c2577f772.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1e063e0ac3759f56ef85b8818e81e68e31d131d2c026ff79ec3cc10d8609dd5"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<amDvKZU.length;i++)if(i%2==0)x.push(amDvKZU[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
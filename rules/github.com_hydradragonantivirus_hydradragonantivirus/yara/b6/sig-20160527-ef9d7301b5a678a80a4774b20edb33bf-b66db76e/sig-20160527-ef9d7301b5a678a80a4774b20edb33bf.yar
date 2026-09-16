rule sig_20160527_ef9d7301b5a678a80a4774b20edb33bf {
  meta:
    description = "datamaliciousorder - file 20160527_ef9d7301b5a678a80a4774b20edb33bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e0896ca52cdfd7ebe59c7ad2512ca71f4ebbeb18a12414199b7bbeb895f22c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aXY32jfU0.length;i++)if(i%2==0)x.push(aXY32jfU0[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
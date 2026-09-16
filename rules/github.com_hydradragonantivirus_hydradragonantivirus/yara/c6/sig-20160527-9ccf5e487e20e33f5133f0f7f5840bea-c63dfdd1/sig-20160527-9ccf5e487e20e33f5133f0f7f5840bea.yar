rule sig_20160527_9ccf5e487e20e33f5133f0f7f5840bea {
  meta:
    description = "datamaliciousorder - file 20160527_9ccf5e487e20e33f5133f0f7f5840bea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a4c32f68c6f28188e0da8035c2fcbc4c8a6bfe740ebc15829b3fe8c7d286e4b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aKonhSJ.length;i++)if(i%2==0)x.push(aKonhSJ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
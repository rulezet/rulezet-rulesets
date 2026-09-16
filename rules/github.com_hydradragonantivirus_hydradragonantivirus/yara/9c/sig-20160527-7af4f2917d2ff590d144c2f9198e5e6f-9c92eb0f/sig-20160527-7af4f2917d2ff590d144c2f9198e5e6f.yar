rule sig_20160527_7af4f2917d2ff590d144c2f9198e5e6f {
  meta:
    description = "datamaliciousorder - file 20160527_7af4f2917d2ff590d144c2f9198e5e6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "618fefe8b99e17c6a36113f1453e4203ec22f7f6b886a2e5ed8e283d7daff4dc"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<anp2x33C2.length;i++)if(i%2==0)x.push(anp2x33C2[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
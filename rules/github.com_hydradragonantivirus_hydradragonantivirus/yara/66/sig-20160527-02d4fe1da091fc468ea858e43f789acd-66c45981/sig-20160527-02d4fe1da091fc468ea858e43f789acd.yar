rule sig_20160527_02d4fe1da091fc468ea858e43f789acd {
  meta:
    description = "datamaliciousorder - file 20160527_02d4fe1da091fc468ea858e43f789acd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49228b3f8682d6eec6340d28f585c3ece38b377ef740e0a4ade9b2394c708a37"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aBREW27Bt.length;i++)if(i%2==0)x.push(aBREW27Bt[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
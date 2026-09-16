rule sig_20160527_787af8bed57a0e7d67613755db0cadd7 {
  meta:
    description = "datamaliciousorder - file 20160527_787af8bed57a0e7d67613755db0cadd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27f42a60b654b0f86cc57dedc82a5d867d7ae0d6c6d724360c46ee1bc5e0fb4c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aa6M7Kf8TT.length;i++)if(i%2==0)x.push(aa6M7Kf8TT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
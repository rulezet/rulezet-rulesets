rule sig_20160530_b918b6843a71523ac34e39aa8b51518e {
  meta:
    description = "datamaliciousorder - file 20160530_b918b6843a71523ac34e39aa8b51518e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1595d087c53d7e8fe78a75f04ab0492c4c15a2ca5aff782c38f675a06734429"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a6t6uuy1cR.length;i++)if(i%2==0)x.push(a6t6uuy1cR[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160530_0d6101bd96bcb1cef22452463e50a158 {
  meta:
    description = "datamaliciousorder - file 20160530_0d6101bd96bcb1cef22452463e50a158.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e605dbb6cff385a3b392140cdedd4afe64fe4999b8f6b31bb6cc9e01a8b84609"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<anvxAcjbR.length;i++)if(i%2==0)x.push(anvxAcjbR[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
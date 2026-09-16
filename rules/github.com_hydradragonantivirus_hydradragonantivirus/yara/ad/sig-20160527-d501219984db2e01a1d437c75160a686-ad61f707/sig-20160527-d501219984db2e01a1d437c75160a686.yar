rule sig_20160527_d501219984db2e01a1d437c75160a686 {
  meta:
    description = "datamaliciousorder - file 20160527_d501219984db2e01a1d437c75160a686.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d0c448d71fa8eee0c45c2d3dd2ce59756654f6ce5e44b962c9de909a6a7f62"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aUMWi3.length;i++)if(i%2==0)x.push(aUMWi3[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
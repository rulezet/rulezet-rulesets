rule sig_20160527_ba4252686bfc0efd6f13d5ca48e6c298 {
  meta:
    description = "datamaliciousorder - file 20160527_ba4252686bfc0efd6f13d5ca48e6c298.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1cb63e4ae27be88ac466c972ea53901137e8b6796ced1c7518f710f6050e8d3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ajwMEU.length;i++)if(i%2==0)x.push(ajwMEU[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_7bdf12f9382fba69fc73cc2a62583348 {
  meta:
    description = "datamaliciousorder - file 20160527_7bdf12f9382fba69fc73cc2a62583348.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b21a8df5ca61e882f9713a9176bfcffbf28dc5351740f8827948cc052cc8d7bb"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aZWz0zL.length;i++)if(i%2==0)x.push(aZWz0zL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
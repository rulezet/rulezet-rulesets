rule sig_20160530_45d069e299016937c7009f1a22f77efb {
  meta:
    description = "datamaliciousorder - file 20160530_45d069e299016937c7009f1a22f77efb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace315165b8f7d1a3f467c1863b44caad90d93e932869b921bf3521059f686ed"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<acC6k3fVT0.length;i++)if(i%2==0)x.push(acC6k3fVT0[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_c63e4a0209914a13a2c57d543c519569 {
  meta:
    description = "datamaliciousorder - file 20160527_c63e4a0209914a13a2c57d543c519569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7f5f2fbd163e3b9ce734aaed3291a3f43f7f87e9ba692a4d9a28f62a2890dc9"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aaLfBp.length;i++)if(i%2==0)x.push(aaLfBp[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
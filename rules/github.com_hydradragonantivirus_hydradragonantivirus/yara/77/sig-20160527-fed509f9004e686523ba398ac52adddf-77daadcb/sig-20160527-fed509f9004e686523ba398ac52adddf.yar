rule sig_20160527_fed509f9004e686523ba398ac52adddf {
  meta:
    description = "datamaliciousorder - file 20160527_fed509f9004e686523ba398ac52adddf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf1a48da801257c7889a0a18b206910c55671426692d8d0e0a6fa9bc4688c84"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a2ccolM.length;i++)if(i%2==0)x.push(a2ccolM[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
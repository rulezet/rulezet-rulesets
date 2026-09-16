rule sig_20160527_91ae21b3f9786c963839d8ff2cac3f0b {
  meta:
    description = "datamaliciousorder - file 20160527_91ae21b3f9786c963839d8ff2cac3f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a93546d9f993e3066453d84d45730d9f493548ecb43337db001d2dbf0e9ac9fc"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<asCq3vX4fnm.length;i++)if(i%2==0)x.push(asCq3vX4fnm[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
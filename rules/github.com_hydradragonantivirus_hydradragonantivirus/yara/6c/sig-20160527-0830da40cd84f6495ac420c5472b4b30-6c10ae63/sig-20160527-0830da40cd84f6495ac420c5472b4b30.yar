rule sig_20160527_0830da40cd84f6495ac420c5472b4b30 {
  meta:
    description = "datamaliciousorder - file 20160527_0830da40cd84f6495ac420c5472b4b30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bbc604ec1ca442722c871ffda89305968265ad2d9d0d043a54369d5d2605f0d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a7P8Z3Zom.length;i++)if(i%2==0)x.push(a7P8Z3Zom[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
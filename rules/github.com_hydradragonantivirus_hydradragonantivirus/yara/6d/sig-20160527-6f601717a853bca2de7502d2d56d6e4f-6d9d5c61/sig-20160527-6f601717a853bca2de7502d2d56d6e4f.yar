rule sig_20160527_6f601717a853bca2de7502d2d56d6e4f {
  meta:
    description = "datamaliciousorder - file 20160527_6f601717a853bca2de7502d2d56d6e4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f4cfa36150e63652ed337241211da66870fa87115ae5d8bf6a3dfd9104ec789"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aDu2ASNF.length;i++)if(i%2==0)x.push(aDu2ASNF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
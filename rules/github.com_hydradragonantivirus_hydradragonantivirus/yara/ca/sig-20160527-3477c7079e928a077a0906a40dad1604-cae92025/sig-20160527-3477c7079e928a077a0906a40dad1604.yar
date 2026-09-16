rule sig_20160527_3477c7079e928a077a0906a40dad1604 {
  meta:
    description = "datamaliciousorder - file 20160527_3477c7079e928a077a0906a40dad1604.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc8a585b018178e18a43eeb3435222c039bc34feb54918c585f9101c7f6d6076"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a4WtId.length;i++)if(i%2==0)x.push(a4WtId[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
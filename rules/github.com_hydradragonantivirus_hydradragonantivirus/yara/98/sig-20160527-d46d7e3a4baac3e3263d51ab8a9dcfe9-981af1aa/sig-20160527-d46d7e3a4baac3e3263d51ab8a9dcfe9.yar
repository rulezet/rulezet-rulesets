rule sig_20160527_d46d7e3a4baac3e3263d51ab8a9dcfe9 {
  meta:
    description = "datamaliciousorder - file 20160527_d46d7e3a4baac3e3263d51ab8a9dcfe9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51c2c35fa6dfedd6b3140f77b13ac52281c66956461789b9fbefc1d65d225179"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aD155P1ZrBo.length;i++)if(i%2==0)x.push(aD155P1ZrBo[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_88424e51d395dbe2c389caf968c9bf94 {
  meta:
    description = "datamaliciousorder - file 20160527_88424e51d395dbe2c389caf968c9bf94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58b46440ce93d30be3ad25fd378720ba27ea26da9a4069b55303abfd078f0eb7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aFi4R3FH.length;i++)if(i%2==0)x.push(aFi4R3FH[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
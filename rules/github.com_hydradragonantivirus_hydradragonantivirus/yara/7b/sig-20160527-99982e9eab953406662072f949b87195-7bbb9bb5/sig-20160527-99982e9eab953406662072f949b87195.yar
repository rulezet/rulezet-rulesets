rule sig_20160527_99982e9eab953406662072f949b87195 {
  meta:
    description = "datamaliciousorder - file 20160527_99982e9eab953406662072f949b87195.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d677aa190677daaa957019cba279e8edc1a8d65e7f797683640c29f6984b3b6d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aXuvXlM.length;i++)if(i%2==0)x.push(aXuvXlM[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_208edc0128009320654c601565c469d4 {
  meta:
    description = "datamaliciousorder - file 20160527_208edc0128009320654c601565c469d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3cab71753f2b13d3e90a10f239896ffeb1dadf2b12818de01c6ccb771b570d5"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ajYDtW7Sj9.length;i++)if(i%2==0)x.push(ajYDtW7Sj9[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
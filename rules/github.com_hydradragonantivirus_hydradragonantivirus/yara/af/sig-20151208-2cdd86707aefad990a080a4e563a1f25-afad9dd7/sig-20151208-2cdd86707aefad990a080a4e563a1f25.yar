rule sig_20151208_2cdd86707aefad990a080a4e563a1f25 {
  meta:
    description = "datamaliciousorder - file 20151208_2cdd86707aefad990a080a4e563a1f25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "757a10356c74e2ff0556560c3fa32fbd5f835b296d84bf87b6bf9bc057d8009d"

  strings:
    $s1  = "function kmkBPwg(qbDnoPjZMPMfcXuhJDTKUVOsIceYvztbveLW) {return !isNaN(parseFloat(qbDnoPjZMPMfcXuhJDTKUVOsIceYvztbveLW)) && isFin" ascii
    $s2  = "function kmkBPwg(qbDnoPjZMPMfcXuhJDTKUVOsIceYvztbveLW) {return !isNaN(parseFloat(qbDnoPjZMPMfcXuhJDTKUVOsIceYvztbveLW)) && isFin" ascii
    $s3  = "function tcbUVgQzbdh(PCTUHbst,HSBmga){return PCTUHbst.split(HSBmga)}" fullword ascii
    $s4  = "push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"89\");T.push(\"76\");T.push(\"122\");T.push(\"32\");T.push(\"61\");T.push(\"" ascii
    $s5  = "push(\"50\");j.push(\"56\");j.push(\"51\");j.push(\"49\");j.push(\"56\");j.push(\"44\");j.push(\"32\");j.push(\"34\");j.push(\"1" ascii
    $s6  = "push(\"50\");j.push(\"57\");j.push(\"52\");j.push(\"57\");j.push(\"52\");j.push(\"55\");j.push(\"59\");j.push(\"13\");j.push(\"1" ascii
    $s7  = "push(\"120\");j.push(\"112\");j.push(\"97\");j.push(\"110\");j.push(\"100\");j.push(\"69\");j.push(\"110\");j.push(\"118\");j.pu" ascii
    $s8  = "push(\"34\");T.push(\"44\");T.push(\"52\");T.push(\"45\");T.push(\"50\");T.push(\"41\");T.push(\"59\");T.push(\"32\");T.push(\"1" ascii
    $s9  = "function AbakNXTVqfqjDOiaB(bypOd){pOfcUUCwtas= '';for(uABhAQtUdwh=(-854+854)/930; uABhAQtUdwh < (1015+31)/523; uABhAQtUdwh++) {e" ascii
    $s10 = "CeRYaMmM[uABhAQtUdwh]=(-734+734)/998; while(true) { if(eCeRYaMmM[uABhAQtUdwh] > bypOd[uABhAQtUdwh].length-(129+123)/252) { break" ascii
    $s11 = "push(\"72\");j.push(\"32\");j.push(\"61\");j.push(\"32\");j.push(\"88\");j.push(\"97\");j.push(\"103\");j.push(\"32\");j.push(\"" ascii
    $s12 = "function fOKtjWCRFQhFirZlUUwshMbgFtadFynCNtWpOgUrCopQGsOCFNtsfw(siBclzSYqtRkP,ubPvGretHnVzrQ){ return rVdVhRVYPYgdQ[JZEjA(siBclz" ascii
    $s13 = "push(\"13\");T.push(\"10\");T.push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"115\");T.push(\"75\");T.push(\"" ascii
    $s14 = ";return IUDGg;}function dXKrmzDRswhasUh(VHIuJmYbAqBXJqdBX){eval(VHIuJmYbAqBXJqdBX)}" fullword ascii
    $s15 = "push(\"117\");j.push(\"101\");j.push(\"32\");j.push(\"32\");j.push(\"44\");j.push(\"32\");j.push(\"121\");j.push(\"115\");j.push" ascii
    $s16 = "push(\"59\");T.push(\"32\");T.push(\"105\");T.push(\"102\");T.push(\"32\");T.push(\"40\");T.push(\"90\");T.push(\"69\");T.push(" ascii
    $s17 = "var rVdVhRVYPYgdQ=[];for(oVCRnxs=(-856+856)/544;oVCRnxs<(94303+289)/739;oVCRnxs++){rVdVhRVYPYgdQ[oVCRnxs]=String.fromCharCode(oV" ascii
    $s18 = "} return pOfcUUCwtas}" fullword ascii
    $s19 = "function fOKtjWCRFQhFirZlUUwshMbgFtadFynCNtWpOgUrCopQGsOCFNtsfw(siBclzSYqtRkP,ubPvGretHnVzrQ){ return rVdVhRVYPYgdQ[JZEjA(siBclz" ascii
    $s20 = "CRnxs)}function JZEjA(jjqAuhQOTgx,yVnAhfYyfPgHF,MQmxIbTt){SoPs=parseInt(jjqAuhQOTgx,yVnAhfYyfPgHF);IUDGg=SoPs.toString(MQmxIbTt)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
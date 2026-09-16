rule sig_20151208_bd8207006208b21632d1f146a7de3c87 {
  meta:
    description = "datamaliciousorder - file 20151208_bd8207006208b21632d1f146a7de3c87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a36a3f28284446ce35cb598c2ec2d08d165b74c5389191e59ecae73e524a34ca"

  strings:
    $s1  = "function FTZmLLb(HIVyEPMIVhpfEZXfWGxlBDQbiIDmTODPjUpI) {return !isNaN(parseFloat(HIVyEPMIVhpfEZXfWGxlBDQbiIDmTODPjUpI)) && isFin" ascii
    $s2  = "function FTZmLLb(HIVyEPMIVhpfEZXfWGxlBDQbiIDmTODPjUpI) {return !isNaN(parseFloat(HIVyEPMIVhpfEZXfWGxlBDQbiIDmTODPjUpI)) && isFin" ascii
    $s3  = "push(\"108\");P.push(\"117\");P.push(\"100\");P.push(\"101\");P.push(\"115\");P.push(\"47\");P.push(\"112\");P.push(\"111\");P.p" ascii
    $s4  = "var RYcuteHlZnqne=[];for(HQPIqNF=(-536+536)/748;HQPIqNF<(39971+477)/316;HQPIqNF++){RYcuteHlZnqne[HQPIqNF]=String.fromCharCode(HQ" ascii
    $s5  = "push(\"95\");P.push(\"112\");P.push(\"97\");P.push(\"103\");P.push(\"101\");P.push(\"115\");P.push(\"95\");P.push(\"115\");P.pus" ascii
    $s6  = "function SGDhOcvjHGL(MMkfyQFf,tuZDQi){return MMkfyQFf.split(tuZDQi)}" fullword ascii
    $s7  = "function yyZQgpYDJwLGWkpvzhbZyuCHvmOzWdybsMWXBvxPgfKwCSPgdbtrae(kBxiThNIPvFdL,Pnjnkffaafdehh){ return RYcuteHlZnqne[aPZci(kBxiTh" ascii
    $s8  = "function yyZQgpYDJwLGWkpvzhbZyuCHvmOzWdybsMWXBvxPgfKwCSPgdbtrae(kBxiThNIPvFdL,Pnjnkffaafdehh){ return RYcuteHlZnqne[aPZci(kBxiTh" ascii
    $s9  = "push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"99\");J.push(\"97\");J.push(\"116\");J.push(\"" ascii
    $s10 = "push(\"125\");J.push(\"59\");J.push(\"32\");J.push(\"13\");J.push(\"10\");J.push(\"125\");J.push(\"59\");J.push(\"32\");J.push(" ascii
    $s11 = "push(\"68\");J.push(\"97\");J.push(\"116\");J.push(\"101\");J.push(\"40\");J.push(\"41\");J.push(\"41\");J.push(\"62\");J.push(" ascii
    $s12 = "push(\"61\");J.push(\"32\");J.push(\"54\");J.push(\"50\");J.push(\"53\");J.push(\"48\");J.push(\"55\");J.push(\"55\");J.push(\"5" ascii
    $s13 = "OzhJjqsgA[MpgxNWGrZFI]=(-3+3)/594; while(true) { if(OzhJjqsgA[MpgxNWGrZFI] > SKkPy[MpgxNWGrZFI].length-(-613+838)/225) { break; " ascii
    $s14 = "push(\"77\");P.push(\"80\");P.push(\"37\");P.push(\"92\");P.push(\"92\");P.push(\"34\");P.push(\"59\");P.push(\"13\");P.push(\"1" ascii
    $s15 = "push(\"121\");J.push(\"116\");J.push(\"42\");J.push(\"47\");J.push(\"51\");J.push(\"45\");J.push(\"50\");J.push(\"44\");J.push(" ascii
    $s16 = ";return jssVl;}function ExDcCvxYvmUCgDX(lKOmwfHrWbevXgHqd){eval(lKOmwfHrWbevXgHqd)}" fullword ascii
    $s17 = "push(\"59\");J.push(\"13\");J.push(\"10\");J.push(\"118\");J.push(\"97\");J.push(\"114\");J.push(\"32\");J.push(\"113\");J.push(" ascii
    $s18 = "push(\"32\");J.push(\"61\");J.push(\"32\");J.push(\"34\");J.push(\"71\");J.push(\"69\");J.push(\"84\");J.push(\"34\");J.push(\"5" ascii
    $s19 = "} return ZsQFepWRQMY}" fullword ascii
    $s20 = "function WAHjFlzzVCkGkiQuR(SKkPy){ZsQFepWRQMY= '';for(MpgxNWGrZFI=(-793+793)/818; MpgxNWGrZFI < (1331+663)/997; MpgxNWGrZFI++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
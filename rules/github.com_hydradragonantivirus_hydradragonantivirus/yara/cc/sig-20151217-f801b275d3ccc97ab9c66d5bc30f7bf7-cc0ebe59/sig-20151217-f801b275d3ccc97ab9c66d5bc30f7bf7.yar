rule sig_20151217_f801b275d3ccc97ab9c66d5bc30f7bf7 {
  meta:
    description = "datamaliciousorder - file 20151217_f801b275d3ccc97ab9c66d5bc30f7bf7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0102927e5d50002ae802c67a0d4294e15a324550adb9b342220bf60902e286c6"

  strings:
    $s1  = "function rKzUBSmKWzinXDRAR(xFnYt){sHEuZzpXEhV= '';DolbhHojBlO=Math.round((Math.pow(Math.sin(292), 2) + Math.pow(Math.cos(292), 2" ascii
    $s2  = "th.pow(Math.cos(169), 2) - 1)); while(true) { if(hPPcMuBco[DolbhHojBlO] > xFnYt[DolbhHojBlO].length-(-15+467)/452) { break; } if" ascii
    $s3  = "ow(Math.cos(110), 2) - 1)));} hPPcMuBco[DolbhHojBlO]++;}DolbhHojBlO++;} return sHEuZzpXEhV}" fullword ascii
    $s4  = ") - 1));while(true){if (DolbhHojBlO >= (-177+903)/121){break;}hPPcMuBco[DolbhHojBlO]=Math.round((Math.pow(Math.sin(169), 2) + Ma" ascii
    $s5  = "function rKzUBSmKWzinXDRAR(xFnYt){sHEuZzpXEhV= '';DolbhHojBlO=Math.round((Math.pow(Math.sin(292), 2) + Math.pow(Math.cos(292), 2" ascii
    $s6  = "function PTwtYobcYbOopcQJaRMsOKRmAzFjXXszZXhZfwAeyewMOBbRSruIDP(NPdmWnFuxtqnR,SbQMCwwZFxPjaE){ return DUFElZu[JUuGUqXG[Yycfl(NPd" ascii
    $s7  = "function PTwtYobcYbOopcQJaRMsOKRmAzFjXXszZXhZfwAeyewMOBbRSruIDP(NPdmWnFuxtqnR,SbQMCwwZFxPjaE){ return DUFElZu[JUuGUqXG[Yycfl(NPd" ascii
    $s8  = "function CqxwfWF(jzjkqJVHjQChQwxKsjxEkroJchxRZOVfAATw) {return !BtYlsjxHXiB(zLhHEgADmpPKoLx(jzjkqJVHjQChQwxKsjxEkroJchxRZOVfAATw" ascii
    $s9  = "function BtYlsjxHXiB(zIqqLAhAMYnMNB) {return isNaN(zIqqLAhAMYnMNB);}" fullword ascii
    $s10 = "function oJDQnQHhBcXR(SfQnTmTbxGLEC) {return isFinite(SfQnTmTbxGLEC);}" fullword ascii
    $s11 = "function bZPywUaIruVsQfnBj(mMTcrHdySx,vIBsrSWZZy) {return parseInt(mMTcrHdySx,vIBsrSWZZy);}" fullword ascii
    $s12 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s13 = "function Yycfl(KdhdfCQIVQN,JCIyAlAPbuxiJ,nSuwsiow){Azqv=bZPywUaIruVsQfnBj(KdhdfCQIVQN,JCIyAlAPbuxiJ);gmuUv=Azqv.toString(nSuwsio" ascii
    $s14 = "w);return gmuUv;}" fullword ascii
    $s15 = "function zLhHEgADmpPKoLx(pJJeYskBfBtINqNMjMp) {return parseFloat(pJJeYskBfBtINqNMjMp);}" fullword ascii
    $s16 = "function E(lCXjcnrSGGxE,rXWEXdACoVpVMU){lCXjcnrSGGxE.push(rXWEXdACoVpVMU);}" fullword ascii
    $s17 = "function CqxwfWF(jzjkqJVHjQChQwxKsjxEkroJchxRZOVfAATw) {return !BtYlsjxHXiB(zLhHEgADmpPKoLx(jzjkqJVHjQChQwxKsjxEkroJchxRZOVfAATw" ascii
    $s18 = "function w(gjNrOWDPWAzPHC,HNsecSDNmdegk,conionOuEkC) {gjNrOWDPWAzPHC[HNsecSDNmdegk]=conionOuEkC;}" fullword ascii
    $s19 = "function Yycfl(KdhdfCQIVQN,JCIyAlAPbuxiJ,nSuwsiow){Azqv=bZPywUaIruVsQfnBj(KdhdfCQIVQN,JCIyAlAPbuxiJ);gmuUv=Azqv.toString(nSuwsio" ascii
    $s20 = "function dtkkjHcvNoAFRJQ(cWjBPcFgkVNVoTkGV,DysQpEpPxGxFdIfItEzdoQXvEOysbiqRbg,EmevUWLBsCauALMVrkHIXTCJKYfxZAofGSV){eval(cWjBPcFg" ascii

  condition:
    uint16(0) == 0x554a and
    8 of them
}
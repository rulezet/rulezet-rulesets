rule sig_20151216_43f90a1847bed7a9701db5d67863500e {
  meta:
    description = "datamaliciousorder - file 20151216_43f90a1847bed7a9701db5d67863500e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e064876476784b6b00a68eb709770e1e2d87ef3989e5cc4544b4e537c4f4d6c7"

  strings:
    $s1  = "th.pow(Math.cos(292), 2) - 1)); while(true) { if(QcQoMNhbo[NAnyhUfeuxm] > IBDZE[NAnyhUfeuxm].length-(269+318)/587) { break; } if" ascii
    $s2  = ") - 1));while(true){if (NAnyhUfeuxm >= (2302+290)/432){break;}QcQoMNhbo[NAnyhUfeuxm]=Math.round((Math.pow(Math.sin(292), 2) + Ma" ascii
    $s3  = "function JNAFgFodsfoAgUOXz(IBDZE){QOyMrXrNDOQ= '';NAnyhUfeuxm=Math.round((Math.pow(Math.sin(422), 2) + Math.pow(Math.cos(422), 2" ascii
    $s4  = "ow(Math.cos(155), 2) - 1)));} QcQoMNhbo[NAnyhUfeuxm]++;}NAnyhUfeuxm++;} return QOyMrXrNDOQ}" fullword ascii
    $s5  = "function JNAFgFodsfoAgUOXz(IBDZE){QOyMrXrNDOQ= '';NAnyhUfeuxm=Math.round((Math.pow(Math.sin(422), 2) + Math.pow(Math.cos(422), 2" ascii
    $s6  = "function PMtFpJt(aoyZvCUiCndnWIsJXZnyPetpPraqknCSqfpa) {return !xGmyDvdwWhV(KPulKYbjJcMMFYs(aoyZvCUiCndnWIsJXZnyPetpPraqknCSqfpa" ascii
    $s7  = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s8  = "function cfXRM(qKehdmpBJrn,zSpBvNKTZgjNI,JFbiknDw){NbtM=gNieGJhvJLXYnMYgb(qKehdmpBJrn,zSpBvNKTZgjNI);gANsz=NbtM.toString(JFbiknD" ascii
    $s9  = "function h(DBpPtkuNmRYtFK,SfWhJFYUyBVuA,xEAhUOJoJuT) {DBpPtkuNmRYtFK[SfWhJFYUyBVuA]=xEAhUOJoJuT;}" fullword ascii
    $s10 = "function xGmyDvdwWhV(ZmrbFOPDlmNjTC) {return isNaN(ZmrbFOPDlmNjTC);}" fullword ascii
    $s11 = "function copXazhRFoQbmoITvzOfitsxTnvxeGfhxBwbYxtVdJSFjHgWPGcsWD(hzDYvxfgRIXES,NGmhaAOUEbbkGa){ return ASJjTXf[LPTRWZEF[cfXRM(hzD" ascii
    $s12 = "function oJbHNxpqDubILZE(dPZJaGhWXFPpgDbLW,mYpYFaawmXnmwJRXfCxeOoVLzznaAqqKKz,GlIwLLPLzEGhObQGqvFjUXjfGqJSlnfYirA){eval(dPZJaGhW" ascii
    $s13 = "function gNieGJhvJLXYnMYgb(tPcwPJtMgH,BdSAtwCltB) {return parseInt(tPcwPJtMgH,BdSAtwCltB);}" fullword ascii
    $s14 = "function O(pHoRXaQlyiud,yAEZxWwaRSluhl){pHoRXaQlyiud.push(yAEZxWwaRSluhl);}" fullword ascii
    $s15 = "function cfXRM(qKehdmpBJrn,zSpBvNKTZgjNI,JFbiknDw){NbtM=gNieGJhvJLXYnMYgb(qKehdmpBJrn,zSpBvNKTZgjNI);gANsz=NbtM.toString(JFbiknD" ascii
    $s16 = "function PMtFpJt(aoyZvCUiCndnWIsJXZnyPetpPraqknCSqfpa) {return !xGmyDvdwWhV(KPulKYbjJcMMFYs(aoyZvCUiCndnWIsJXZnyPetpPraqknCSqfpa" ascii
    $s17 = "function KPulKYbjJcMMFYs(ijONZuEIIgZEbQTFbKz) {return parseFloat(ijONZuEIIgZEbQTFbKz);}" fullword ascii
    $s18 = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s19 = "function copXazhRFoQbmoITvzOfitsxTnvxeGfhxBwbYxtVdJSFjHgWPGcsWD(hzDYvxfgRIXES,NGmhaAOUEbbkGa){ return ASJjTXf[LPTRWZEF[cfXRM(hzD" ascii
    $s20 = "w);return gANsz;}" fullword ascii

  condition:
    uint16(0) == 0x504c and
    8 of them
}
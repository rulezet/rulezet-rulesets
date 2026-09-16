rule sig_20151217_1e87d64950c8cc01d3331ff69aeee5dc {
  meta:
    description = "datamaliciousorder - file 20151217_1e87d64950c8cc01d3331ff69aeee5dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07f89847b50ca03fd1284ef2425f7284bd1c26816d5a86bccfc5e5f35060beac"

  strings:
    $s1  = "ow(Math.cos(368), 2) - 1)));} ELugDYssp[vgvCkLhyRXT]++;}vgvCkLhyRXT++;} return PJZbcNEsWno}" fullword ascii
    $s2  = "th.pow(Math.cos(793), 2) - 1)); while(true) { if(ELugDYssp[vgvCkLhyRXT] > zTaaK[vgvCkLhyRXT].length-(147+266)/413) { break; } if" ascii
    $s3  = ") - 1));while(true){if (vgvCkLhyRXT >= (2824+890)/619){break;}ELugDYssp[vgvCkLhyRXT]=Math.round((Math.pow(Math.sin(793), 2) + Ma" ascii
    $s4  = "function fBqbzaKPnfgxAumqP(zTaaK){PJZbcNEsWno= '';vgvCkLhyRXT=Math.round((Math.pow(Math.sin(435), 2) + Math.pow(Math.cos(435), 2" ascii
    $s5  = "function fUmmePU(ALfrOdvBjPDTYixGVmygGjmXgkmeEzWYyznJ) {return !jeavNTFTDWR(oviRcWMTuTRMerp(ALfrOdvBjPDTYixGVmygGjmXgkmeEzWYyznJ" ascii
    $s6  = "function fBqbzaKPnfgxAumqP(zTaaK){PJZbcNEsWno= '';vgvCkLhyRXT=Math.round((Math.pow(Math.sin(435), 2) + Math.pow(Math.cos(435), 2" ascii
    $s7  = "function oviRcWMTuTRMerp(WsGyqaVaeMHUpKDxKKF) {return parseFloat(WsGyqaVaeMHUpKDxKKF);}" fullword ascii
    $s8  = "function fUmmePU(ALfrOdvBjPDTYixGVmygGjmXgkmeEzWYyznJ) {return !jeavNTFTDWR(oviRcWMTuTRMerp(ALfrOdvBjPDTYixGVmygGjmXgkmeEzWYyznJ" ascii
    $s9  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s10 = "function kpNVEQSlCbMEpnD(ajBNnYrjdYgXmUjif,YzqwyNxbviDegFYjwFBaeWBAGlWZRQEsTC,WOCbWuHDXJOHIlQSYDmFetreUGwnnMDHizR){eval(ajBNnYrj" ascii
    $s11 = "function B(EuZzoxhCgLmptP,ZyDRWZORXSLbj,VGNrvYnwdnm) {EuZzoxhCgLmptP[ZyDRWZORXSLbj]=VGNrvYnwdnm;}" fullword ascii
    $s12 = "function i(rmrJUMhVogiS,vQowgkuFjjTsan){rmrJUMhVogiS.push(vQowgkuFjjTsan);}" fullword ascii
    $s13 = "function JVYlV(HxwhaBmDoAZ,hCxmKErbcRfWn,IplMhGmv){dEat=weQbtodnxCVWTSDgx(HxwhaBmDoAZ,hCxmKErbcRfWn);cxwmN=dEat.toString(IplMhGm" ascii
    $s14 = "function YGzcmvuEnBxkPUWhTLGxhLkCHiXDmLeJFfjCquOktNIlwhEwwNtcTt(HSyoUIDvEreny,YhOrSvMQpgdPsR){ return bTJctea[MqcZVgWp[JVYlV(HSy" ascii
    $s15 = "function JVYlV(HxwhaBmDoAZ,hCxmKErbcRfWn,IplMhGmv){dEat=weQbtodnxCVWTSDgx(HxwhaBmDoAZ,hCxmKErbcRfWn);cxwmN=dEat.toString(IplMhGm" ascii
    $s16 = "function LMiObvpqIseH(uJDjqHRaaSfSA) {return isFinite(uJDjqHRaaSfSA);}" fullword ascii
    $s17 = "function jeavNTFTDWR(QtFBnKAxpGgefa) {return isNaN(QtFBnKAxpGgefa);}" fullword ascii
    $s18 = "function YGzcmvuEnBxkPUWhTLGxhLkCHiXDmLeJFfjCquOktNIlwhEwwNtcTt(HSyoUIDvEreny,YhOrSvMQpgdPsR){ return bTJctea[MqcZVgWp[JVYlV(HSy" ascii
    $s19 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s20 = "v);return cxwmN;}" fullword ascii

  condition:
    uint16(0) == 0x714d and
    8 of them
}
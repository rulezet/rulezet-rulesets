rule sig_20151217_092b40bf25e85ad4c5fcb88d994d9359 {
  meta:
    description = "datamaliciousorder - file 20151217_092b40bf25e85ad4c5fcb88d994d9359.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5df51cb20e8e8a9cae7ee8842b9b9008c53d5c8a0719cce19132212065242df4"

  strings:
    $s1  = "w(Math.cos(851), 2) - 1)));} zarfGFnuo[ragjdtinEpI]++;}ragjdtinEpI++;} return qNCdMphPAze}" fullword ascii
    $s2  = "th.pow(Math.cos(971), 2) - 1)); while(true) { if(zarfGFnuo[ragjdtinEpI] > gWJMG[ragjdtinEpI].length-(103+542)/645) { break; } if" ascii
    $s3  = ") - 1));while(true){if (ragjdtinEpI >= (3599+481)/680){break;}zarfGFnuo[ragjdtinEpI]=Math.round((Math.pow(Math.sin(971), 2) + Ma" ascii
    $s4  = "function MeCohhLrktTNUqDwC(gWJMG){qNCdMphPAze= '';ragjdtinEpI=Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.cos(804), 2" ascii
    $s5  = "function MeCohhLrktTNUqDwC(gWJMG){qNCdMphPAze= '';ragjdtinEpI=Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.cos(804), 2" ascii
    $s6  = "function E(ndBPCSAMUKqk,sGkIOtBYQrgdOH){ndBPCSAMUKqk.push(sGkIOtBYQrgdOH);}" fullword ascii
    $s7  = "function OVAQMaa(rJTyDTUaNKHtdrjnMofUgtyRqjjSguszELGS) {return !SJUXpsoJZyf(oKrnnNMGYwiLmJo(rJTyDTUaNKHtdrjnMofUgtyRqjjSguszELGS" ascii
    $s8  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s9  = "function OVAQMaa(rJTyDTUaNKHtdrjnMofUgtyRqjjSguszELGS) {return !SJUXpsoJZyf(oKrnnNMGYwiLmJo(rJTyDTUaNKHtdrjnMofUgtyRqjjSguszELGS" ascii
    $s10 = "function uxcmGVSSmqKzGPT(nbxVQXIYgZkrKKPQg,LENxybqIiEHgCOIpTpWHlenHnDZAeePsrI,zcmapivtzSJdJyGgfgXotHyEfBkRYxyfVJg){eval(nbxVQXIY" ascii
    $s11 = "function oKrnnNMGYwiLmJo(SGqJORWoVEPQyBBNDrX) {return parseFloat(SGqJORWoVEPQyBBNDrX);}" fullword ascii
    $s12 = "function YrfoDfZvpTENvscCJ(PeuJXeDheY,zGpnhMmrMu) {return parseInt(PeuJXeDheY,zGpnhMmrMu);}" fullword ascii
    $s13 = "b);return RbIeh;}" fullword ascii
    $s14 = "function uxcmGVSSmqKzGPT(nbxVQXIYgZkrKKPQg,LENxybqIiEHgCOIpTpWHlenHnDZAeePsrI,zcmapivtzSJdJyGgfgXotHyEfBkRYxyfVJg){eval(nbxVQXIY" ascii
    $s15 = "function OoAyK(efKJXZHyOIh,WbsPVikuIsJIK,RJXmMKFb){Axmh=YrfoDfZvpTENvscCJ(efKJXZHyOIh,WbsPVikuIsJIK);RbIeh=Axmh.toString(RJXmMKF" ascii
    $s16 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s17 = "function SJUXpsoJZyf(KVIpTfitBuVTLu) {return isNaN(KVIpTfitBuVTLu);}" fullword ascii
    $s18 = "function d(QcuVDHZKiRxyyB,ynkNWEcJSyiuo,lhoNILrKJpG) {QcuVDHZKiRxyyB[ynkNWEcJSyiuo]=lhoNILrKJpG;}" fullword ascii
    $s19 = "function jaDlfcDnvPNo(UJYNWjyCHYzMj) {return isFinite(UJYNWjyCHYzMj);}" fullword ascii
    $s20 = "function OoAyK(efKJXZHyOIh,WbsPVikuIsJIK,RJXmMKFb){Axmh=YrfoDfZvpTENvscCJ(efKJXZHyOIh,WbsPVikuIsJIK);RbIeh=Axmh.toString(RJXmMKF" ascii

  condition:
    uint16(0) == 0x7959 and
    8 of them
}
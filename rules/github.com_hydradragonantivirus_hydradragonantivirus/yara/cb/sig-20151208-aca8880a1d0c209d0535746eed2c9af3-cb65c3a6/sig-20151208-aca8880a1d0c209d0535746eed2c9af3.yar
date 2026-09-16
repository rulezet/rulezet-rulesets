rule sig_20151208_aca8880a1d0c209d0535746eed2c9af3 {
  meta:
    description = "datamaliciousorder - file 20151208_aca8880a1d0c209d0535746eed2c9af3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f13ce8f24ca00db70835a708801385d0e06fad9afe78dfc7009eec9b1cc4b66d"

  strings:
    $s1  = "function XcSSHlF(hfbrJAaoeEFKITrUOWvFSbuTwxcetDGRTVjH) {return !isNaN(parseFloat(hfbrJAaoeEFKITrUOWvFSbuTwxcetDGRTVjH)) && isFin" ascii
    $s2  = "function XcSSHlF(hfbrJAaoeEFKITrUOWvFSbuTwxcetDGRTVjH) {return !isNaN(parseFloat(hfbrJAaoeEFKITrUOWvFSbuTwxcetDGRTVjH)) && isFin" ascii
    $s3  = "function VXXFcbDoYJzHpfqQF(bTGIW){tTJnXboRmod= '';for(DfuItJIoxIO=(-36+36)/357; DfuItJIoxIO < (149+839)/494; DfuItJIoxIO++) {lTM" ascii
    $s4  = "push(\"123\");Y.push(\"13\");Y.push(\"10\");Y.push(\"32\");Y.push(\"32\");Y.push(\"32\");Y.push(\"32\");Y.push(\"32\");Y.push(\"" ascii
    $s5  = "push(\"41\");Y.push(\"59\");Y.push(\"32\");Y.push(\"105\");Y.push(\"102\");Y.push(\"32\");Y.push(\"40\");Y.push(\"68\");Y.push(" ascii
    $s6  = ";}} return tTJnXboRmod}" fullword ascii
    $s7  = "eturn soQOY;}function oEBUweGotyGIdJn(vOxpWnFJTLFzEmGPO){eval(vOxpWnFJTLFzEmGPO)}" fullword ascii
    $s8  = "ZPh)}function yCoNa(JgoDhQjEYtG,LDzwRflTFmzzq,znxiAhmH){EEGQ=parseInt(JgoDhQjEYtG,LDzwRflTFmzzq);soQOY=EEGQ.toString(znxiAhmH);r" ascii
    $s9  = "push(\"105\");Y.push(\"108\");Y.push(\"101\");Y.push(\"47\");Y.push(\"42\");Y.push(\"100\");Y.push(\"109\");Y.push(\"97\");Y.pus" ascii
    $s10 = "push(\"45\");I.push(\"105\");I.push(\"110\");I.push(\"99\");I.push(\"108\");I.push(\"117\");I.push(\"100\");I.push(\"101\");I.pu" ascii
    $s11 = "function jzfURshDSmH(JQxCdAPQ,GPffhm){return JQxCdAPQ.split(GPffhm)}" fullword ascii
    $s12 = "var tRUlbhhFWHCrp=[];for(TOTIZPh=(-409+409)/274;TOTIZPh<(1689+871)/20;TOTIZPh++){tRUlbhhFWHCrp[TOTIZPh]=String.fromCharCode(TOTI" ascii
    $s13 = "function zGMiLtgXrqzSjhhGRBbpwYiZNsHOkjtueauTmRQZkKEkXCrfhKjcOL(LVnNogZgNNemF,soFIwhrOQtQrrG){ return tRUlbhhFWHCrp[yCoNa(LVnNog" ascii
    $s14 = "function VXXFcbDoYJzHpfqQF(bTGIW){tTJnXboRmod= '';for(DfuItJIoxIO=(-36+36)/357; DfuItJIoxIO < (149+839)/494; DfuItJIoxIO++) {lTM" ascii
    $s15 = "push(\"32\");Y.push(\"43\");Y.push(\"32\");Y.push(\"34\");Y.push(\"66\");Y.push(\"46\");Y.push(\"83\");Y.push(\"116\");Y.push(\"" ascii
    $s16 = "OPErKe[DfuItJIoxIO]=(-189+189)/337; while(true) { if(lTMOPErKe[DfuItJIoxIO] > bTGIW[DfuItJIoxIO].length-(-315+445)/130) { break;" ascii
    $s17 = "push(\"50\");Y.push(\"67\");Y.push(\"105\");Y.push(\"82\");Y.push(\"53\");Y.push(\"55\");Y.push(\"122\");Y.push(\"114\");Y.push(" ascii
    $s18 = "function zGMiLtgXrqzSjhhGRBbpwYiZNsHOkjtueauTmRQZkKEkXCrfhKjcOL(LVnNogZgNNemF,soFIwhrOQtQrrG){ return tRUlbhhFWHCrp[yCoNa(LVnNog" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20151208_a2c621f2c034616eb8d551546393ae1e {
  meta:
    description = "datamaliciousorder - file 20151208_a2c621f2c034616eb8d551546393ae1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4aab5a2935075c4e5e23bfddd81cd2ccb550967d51789b31686efe683587c95"

  strings:
    $s1  = "function MaSaOOM(xLfgwbybSGdccJcXSyyJpPskxJSektRcLaUw) {return !isNaN(parseFloat(xLfgwbybSGdccJcXSyyJpPskxJSektRcLaUw)) && isFin" ascii
    $s2  = "function MaSaOOM(xLfgwbybSGdccJcXSyyJpPskxJSektRcLaUw) {return !isNaN(parseFloat(xLfgwbybSGdccJcXSyyJpPskxJSektRcLaUw)) && isFin" ascii
    $s3  = "function dWhlAsoeVzKxORbPUYQwXJwOoNZeWXVPwFmaVSiOFQTMsVTWHbiZYz(LGzEdLPlUlmDs,DAfEtrCBmpdrzm){ return deQhEXRBEXVyl[DXZga(LGzEdL" ascii
    $s4  = "push(\"118\");w.push(\"97\");w.push(\"114\");w.push(\"32\");w.push(\"74\");w.push(\"61\");w.push(\"110\");w.push(\"67\");w.push(" ascii
    $s5  = "var deQhEXRBEXVyl=[];for(TKiJdVp=(-275+275)/649;TKiJdVp<(87155+269)/683;TKiJdVp++){deQhEXRBEXVyl[TKiJdVp]=String.fromCharCode(TK" ascii
    $s6  = "push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"1" ascii
    $s7  = "push(\"118\");N.push(\"97\");N.push(\"114\");N.push(\"32\");N.push(\"98\");N.push(\"97\");N.push(\"122\");N.push(\"32\");N.push(" ascii
    $s8  = "push(\"111\");w.push(\"100\");w.push(\"121\");w.push(\"41\");w.push(\"59\");w.push(\"32\");w.push(\"105\");w.push(\"102\");w.pus" ascii
    $s9  = "push(\"42\");w.push(\"121\");w.push(\"112\");w.push(\"69\");w.push(\"109\");w.push(\"55\");w.push(\"51\");w.push(\"83\");w.push(" ascii
    $s10 = "push(\"59\");w.push(\"32\");w.push(\"77\");w.push(\"85\");w.push(\"80\");w.push(\"46\");w.push(\"116\");w.push(\"121\");w.push(" ascii
    $s11 = "push(\"47\");N.push(\"105\");N.push(\"109\");N.push(\"97\");N.push(\"103\");N.push(\"101\");N.push(\"115\");N.push(\"47\");N.pus" ascii
    $s12 = "push(\"116\");w.push(\"104\");w.push(\"59\");w.push(\"32\");w.push(\"74\");w.push(\"43\");w.push(\"43\");w.push(\"41\");w.push(" ascii
    $s13 = "push(\"67\");w.push(\"107\");w.push(\"109\");w.push(\"73\");w.push(\"118\");w.push(\"77\");w.push(\"43\");w.push(\"47\");w.push(" ascii
    $s14 = "function aPAWiOtsQEt(kaDrnixl,lZpiCX){return kaDrnixl.split(lZpiCX)}" fullword ascii
    $s15 = "push(\"97\");N.push(\"114\");N.push(\"32\");N.push(\"82\");N.push(\"106\");N.push(\"32\");N.push(\"61\");N.push(\"32\");N.push(" ascii
    $s16 = "function GbtYRjurMPNyZxRYH(cFDHS){BQnomaTNulJ= '';for(XRiaYZsSzYm=(-826+826)/128; XRiaYZsSzYm < (70+740)/405; XRiaYZsSzYm++) {QQ" ascii
    $s17 = "push(\"32\");w.push(\"32\");w.push(\"32\");w.push(\"125\");w.push(\"59\");w.push(\"32\");w.push(\"77\");w.push(\"85\");w.push(\"" ascii
    $s18 = "iJdVp)}function DXZga(gcmNuqKuUte,UirpZnbFwGptI,meuezMaG){GxEv=parseInt(gcmNuqKuUte,UirpZnbFwGptI);GIGym=GxEv.toString(meuezMaG)" ascii
    $s19 = "push(\"54\");w.push(\"55\");w.push(\"50\");w.push(\"104\");w.push(\"102\");w.push(\"70\");w.push(\"90\");w.push(\"42\");w.push(" ascii
    $s20 = "function dWhlAsoeVzKxORbPUYQwXJwOoNZeWXVPwFmaVSiOFQTMsVTWHbiZYz(LGzEdLPlUlmDs,DAfEtrCBmpdrzm){ return deQhEXRBEXVyl[DXZga(LGzEdL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
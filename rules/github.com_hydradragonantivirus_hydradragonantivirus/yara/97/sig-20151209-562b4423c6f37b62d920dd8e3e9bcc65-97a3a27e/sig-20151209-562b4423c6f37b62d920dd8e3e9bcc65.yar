rule sig_20151209_562b4423c6f37b62d920dd8e3e9bcc65 {
  meta:
    description = "datamaliciousorder - file 20151209_562b4423c6f37b62d920dd8e3e9bcc65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d30eb8832da9381b070d416440e5a68246703f88fef8561be7a0c43009651757"

  strings:
    $s1  = "function eLJRmYZ(rGDzHPEOgUGxKhNfsSudfwUowfIdomYWgoft) {return !isNaN(parseFloat(rGDzHPEOgUGxKhNfsSudfwUowfIdomYWgoft)) && isFin" ascii
    $s2  = "function eLJRmYZ(rGDzHPEOgUGxKhNfsSudfwUowfIdomYWgoft) {return !isNaN(parseFloat(rGDzHPEOgUGxKhNfsSudfwUowfIdomYWgoft)) && isFin" ascii
    $s3  = "push(\"59\");a.push(\"32\");a.push(\"13\");a.push(\"10\");a.push(\"32\");a.push(\"32\");a.push(\"125\");a.push(\"13\");a.push(\"" ascii
    $s4  = "var LVafntkQYutFo=[];for(mTwyRhz=(-589+589)/299;mTwyRhz<(49940+620)/395;mTwyRhz++){LVafntkQYutFo[mTwyRhz]=String.fromCharCode(mT" ascii
    $s5  = "push(\"114\");X.push(\"117\");X.push(\"101\");X.push(\"32\");X.push(\"32\");X.push(\"44\");X.push(\"32\");X.push(\"106\");X.push" ascii
    $s6  = "push(\"46\");a.push(\"99\");a.push(\"108\");a.push(\"111\");a.push(\"115\");a.push(\"101\");a.push(\"40\");a.push(\"41\");a.push" ascii
    $s7  = "function anIAySKDABImHZxidrvIthyrSFlTkqbhDQhgyqxWcHOFsqVKCgpxaV(VhRZRpuXLTwVD,nQotVOyhHnsbxI){ return LVafntkQYutFo[Cslwa(VhRZRp" ascii
    $s8  = "push(\"61\");X.push(\"32\");X.push(\"48\");X.push(\"59\");X.push(\"13\");X.push(\"10\");X.push(\"118\");X.push(\"97\");X.push(\"" ascii
    $s9  = "dteOgkS[IQzGmDiGmtP]=(-69+69)/346; while(true) { if(DfdteOgkS[IQzGmDiGmtP] > yleyK[IQzGmDiGmtP].length-(38+798)/836) { break; } " ascii
    $s10 = "function dPAYgZEByWbIFloLh(yleyK){rsLLrvHGkdT= '';for(IQzGmDiGmtP=(-311+311)/75; IQzGmDiGmtP < (820+820)/820; IQzGmDiGmtP++) {Df" ascii
    $s11 = "push(\"59\");a.push(\"32\");a.push(\"101\");a.push(\"100\");a.push(\"70\");a.push(\"46\");a.push(\"112\");a.push(\"111\");a.push" ascii
    $s12 = "push(\"61\");a.push(\"61\");a.push(\"32\");a.push(\"49\");a.push(\"41\");a.push(\"32\");a.push(\"32\");a.push(\"123\");a.push(\"" ascii
    $s13 = ";return zsAhi;}function KUETkjtycDSIAxi(UpynHfoMvGfsFGahI){eval(UpynHfoMvGfsFGahI)}" fullword ascii
    $s14 = "wyRhz)}function Cslwa(SDlGLByIZkX,fYXvUWAuJOlva,DgywNDyA){yaYF=parseInt(SDlGLByIZkX,fYXvUWAuJOlva);zsAhi=yaYF.toString(DgywNDyA)" ascii
    $s15 = " return rsLLrvHGkdT}" fullword ascii
    $s16 = "push(\"47\");X.push(\"42\");X.push(\"65\");X.push(\"104\");X.push(\"101\");X.push(\"51\");X.push(\"52\");X.push(\"57\");X.push(" ascii
    $s17 = "function anIAySKDABImHZxidrvIthyrSFlTkqbhDQhgyqxWcHOFsqVKCgpxaV(VhRZRpuXLTwVD,nQotVOyhHnsbxI){ return LVafntkQYutFo[Cslwa(VhRZRp" ascii
    $s18 = "push(\"32\");a.push(\"32\");a.push(\"32\");a.push(\"32\");a.push(\"32\");a.push(\"99\");a.push(\"97\");a.push(\"116\");a.push(\"" ascii
    $s19 = "push(\"59\");X.push(\"13\");X.push(\"10\");X.push(\"118\");X.push(\"97\");X.push(\"114\");X.push(\"32\");X.push(\"111\");X.push(" ascii
    $s20 = "function dPAYgZEByWbIFloLh(yleyK){rsLLrvHGkdT= '';for(IQzGmDiGmtP=(-311+311)/75; IQzGmDiGmtP < (820+820)/820; IQzGmDiGmtP++) {Df" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
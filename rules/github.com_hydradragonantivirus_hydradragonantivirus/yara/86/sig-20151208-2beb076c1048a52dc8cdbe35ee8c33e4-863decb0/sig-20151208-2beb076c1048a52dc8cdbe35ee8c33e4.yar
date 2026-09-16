rule sig_20151208_2beb076c1048a52dc8cdbe35ee8c33e4 {
  meta:
    description = "datamaliciousorder - file 20151208_2beb076c1048a52dc8cdbe35ee8c33e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea469013a7c5707132044f8466a0dfa37ee526e8151e9c9f72cd06537dae600e"

  strings:
    $s1  = "function HnYKttQ(xjamlqXDIqcxKAuaPJuLRXiAutksRdCoghCD) {return !isNaN(parseFloat(xjamlqXDIqcxKAuaPJuLRXiAutksRdCoghCD)) && isFin" ascii
    $s2  = "function HnYKttQ(xjamlqXDIqcxKAuaPJuLRXiAutksRdCoghCD) {return !isNaN(parseFloat(xjamlqXDIqcxKAuaPJuLRXiAutksRdCoghCD)) && isFin" ascii
    $s3  = "push(\"114\");b.push(\"101\");b.push(\"97\");b.push(\"116\");b.push(\"101\");b.push(\"79\");b.push(\"98\");b.push(\"106\");b.pus" ascii
    $s4  = "function NzyoRWtIXNVoaqkDy(MwhtD){KcssJWzmHnO= '';for(brpJJGvtFFW=(-46+46)/815; brpJJGvtFFW < (203+109)/156; brpJJGvtFFW++) {UOO" ascii
    $s5  = "function TfElyYtMKrptiLCnyYQGerUvNGxceIHoAMxaUpOrWeQmflAgFfYKJU(IJYsYzuiDXbBH,qdEXXFMOtlXoxU){ return JKAOcpimZgeET[BeSEa(IJYsYz" ascii
    $s6  = "function NzyoRWtIXNVoaqkDy(MwhtD){KcssJWzmHnO= '';for(brpJJGvtFFW=(-46+46)/815; brpJJGvtFFW < (203+109)/156; brpJJGvtFFW++) {UOO" ascii
    $s7  = "push(\"49\");b.push(\"44\");b.push(\"32\");b.push(\"104\");b.push(\"98\");b.push(\"97\");b.push(\"41\");b.push(\"41\");b.push(\"" ascii
    $s8  = "push(\"117\");w.push(\"115\");w.push(\"32\");w.push(\"61\");w.push(\"61\");w.push(\"32\");w.push(\"49\");w.push(\"48\");w.push(" ascii
    $s9  = "var JKAOcpimZgeET=[];for(xecfhcw=(-525+525)/325;xecfhcw<(118924+116)/930;xecfhcw++){JKAOcpimZgeET[xecfhcw]=String.fromCharCode(x" ascii
    $s10 = "push(\"32\");w.push(\"48\");w.push(\"59\");w.push(\"13\");w.push(\"10\");w.push(\"32\");w.push(\"32\");w.push(\"116\");w.push(\"" ascii
    $s11 = "push(\"97\");w.push(\"109\");w.push(\"46\");w.push(\"115\");w.push(\"97\");w.push(\"118\");w.push(\"101\");w.push(\"84\");w.push" ascii
    $s12 = "push(\"61\");b.push(\"32\");b.push(\"34\");b.push(\"65\");b.push(\"68\");b.push(\"79\");b.push(\"68\");b.push(\"34\");b.push(\"5" ascii
    $s13 = "push(\"65\");w.push(\"97\");w.push(\"109\");w.push(\"46\");w.push(\"112\");w.push(\"111\");w.push(\"115\");w.push(\"105\");w.pus" ascii
    $s14 = "function TfElyYtMKrptiLCnyYQGerUvNGxceIHoAMxaUpOrWeQmflAgFfYKJU(IJYsYzuiDXbBH,qdEXXFMOtlXoxU){ return JKAOcpimZgeET[BeSEa(IJYsYz" ascii
    $s15 = "push(\"53\");w.push(\"49\");w.push(\"78\");w.push(\"48\");w.push(\"97\");w.push(\"65\");w.push(\"42\");w.push(\"47\");w.push(\"4" ascii
    $s16 = "ecfhcw)}function BeSEa(wiCdnBiINlv,DiDiBfkJpSjrS,zsxpvbMZ){BNxi=parseInt(wiCdnBiINlv,DiDiBfkJpSjrS);IkkNw=BNxi.toString(zsxpvbMZ" ascii
    $s17 = "Axppdy[brpJJGvtFFW]=(-454+454)/386; while(true) { if(UOOAxppdy[brpJJGvtFFW] > MwhtD[brpJJGvtFFW].length-(160+97)/257) { break; }" ascii
    $s18 = "push(\"32\");b.push(\"34\");b.push(\"37\");b.push(\"84\");b.push(\"69\");b.push(\"77\");b.push(\"80\");b.push(\"37\");b.push(\"9" ascii
    $s19 = "push(\"97\");w.push(\"116\");w.push(\"99\");w.push(\"104\");w.push(\"32\");w.push(\"40\");w.push(\"119\");w.push(\"98\");w.push(" ascii
    $s20 = ");return IkkNw;}function qpWSftNfNyUoIlc(SUinMAKFSYUAixDjP){eval(SUinMAKFSYUAixDjP)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20151216_a57709186d91ff931863eca378b8f11a {
  meta:
    description = "datamaliciousorder - file 20151216_a57709186d91ff931863eca378b8f11a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6d35b1bbbf6df3dab62a107ed5f21b0bbfd5afbccef8f728b0998cd35d2650b"

  strings:
    $s1  = "function uZHFolIPxdBtpUpyq(jzLRp){ZqFdcZnHkdj= '';jgjaaGgizmL=Math.round((Math.pow(Math.sin(358), 2) + Math.pow(Math.cos(358), 2" ascii
    $s2  = ") - 1));while(true){if (jgjaaGgizmL >= (4699+323)/837){break;}gEznfdEij[jgjaaGgizmL]=Math.round((Math.pow(Math.sin(877), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(877), 2) - 1)); while(true) { if(gEznfdEij[jgjaaGgizmL] > jzLRp[jgjaaGgizmL].length-(129+141)/270) { break; } if" ascii
    $s4  = "pow(Math.cos(232), 2) - 1)));} gEznfdEij[jgjaaGgizmL]++;}jgjaaGgizmL++;} return ZqFdcZnHkdj}" fullword ascii
    $s5  = "EHwcRnHoDklsHbQOLQcqiYLCJpCcTCiGFQO([jzLRp[jgjaaGgizmL][gEznfdEij[jgjaaGgizmL]]], Math.round((Math.pow(Math.sin(232), 2) + Math." ascii
    $s6  = "function uZHFolIPxdBtpUpyq(jzLRp){ZqFdcZnHkdj= '';jgjaaGgizmL=Math.round((Math.pow(Math.sin(358), 2) + Math.pow(Math.cos(358), 2" ascii
    $s7  = "function uWvuvtH(UWzsBTRQsntlMRmqDApnSrMJcJZzlhOxQrpj) {return !CTdtBJFQNzw(lftytMiICfWUOMf(UWzsBTRQsntlMRmqDApnSrMJcJZzlhOxQrpj" ascii
    $s8  = "function uWvuvtH(UWzsBTRQsntlMRmqDApnSrMJcJZzlhOxQrpj) {return !CTdtBJFQNzw(lftytMiICfWUOMf(UWzsBTRQsntlMRmqDApnSrMJcJZzlhOxQrpj" ascii
    $s9  = "function ffwmPzsqppotwoZoi(VHsunGcTzs,HSyqKbgaiN) {return parseInt(VHsunGcTzs,HSyqKbgaiN);}" fullword ascii
    $s10 = "function F(rPslJQkgSJkw,tdjBPXVdItTTYo){rPslJQkgSJkw.push(tdjBPXVdItTTYo);}" fullword ascii
    $s11 = "function TapckeAqePsdbSfRBXpEHwcRnHoDklsHbQOLQcqiYLCJpCcTCiGFQO(ttTawNFMVlzCV,UhtteyoiYviYKt){ return ZnXjtUC[kVlcOKFX[wpmDs(ttT" ascii
    $s12 = "function DFEZAKOMXJasLRl(KsHhLQnhSjAanZgbL,gJmzBCsiIVTbtwsbQwfIIkmFeYloJIDKGz,jwKbGcrXGQllxTciJONBkErTHXsLfHSbzKl){eval(KsHhLQnh" ascii
    $s13 = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s14 = "function wpmDs(rofctrwIMVN,grqzBYdIzwkTA,aCsfnaMH){bfmW=ffwmPzsqppotwoZoi(rofctrwIMVN,grqzBYdIzwkTA);dUCWK=bfmW.toString(aCsfnaM" ascii
    $s15 = "function lftytMiICfWUOMf(gLmAJcBfcCKncDrWsLy) {return parseFloat(gLmAJcBfcCKncDrWsLy);}" fullword ascii
    $s16 = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s17 = "function TapckeAqePsdbSfRBXpEHwcRnHoDklsHbQOLQcqiYLCJpCcTCiGFQO(ttTawNFMVlzCV,UhtteyoiYviYKt){ return ZnXjtUC[kVlcOKFX[wpmDs(ttT" ascii
    $s18 = "function CTdtBJFQNzw(CYDretbYpXBzpf) {return isNaN(CYDretbYpXBzpf);}" fullword ascii
    $s19 = "function DFEZAKOMXJasLRl(KsHhLQnhSjAanZgbL,gJmzBCsiIVTbtwsbQwfIIkmFeYloJIDKGz,jwKbGcrXGQllxTciJONBkErTHXsLfHSbzKl){eval(KsHhLQnh" ascii
    $s20 = "H);return dUCWK;}" fullword ascii

  condition:
    uint16(0) == 0x566b and
    8 of them
}
rule sig_20151217_1ae382e055268baa0581bda1a192d5e6 {
  meta:
    description = "datamaliciousorder - file 20151217_1ae382e055268baa0581bda1a192d5e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c2e9400f3146bf0a16ccdf55d19cdfbfa3e27c56c5ff75548ea619d1cde740"

  strings:
    $s1  = "function tntZVvZXhdBOJhbqr(nraNU){ECJpyeRhaqz= '';cJXfdAIRCna=Math.round((Math.pow(Math.sin(558), 2) + Math.pow(Math.cos(558), 2" ascii
    $s2  = ") - 1));while(true){if (cJXfdAIRCna >= (4301+139)/740){break;}PiVZqyVTy[cJXfdAIRCna]=Math.round((Math.pow(Math.sin(732), 2) + Ma" ascii
    $s3  = "w(Math.cos(214), 2) - 1)));} PiVZqyVTy[cJXfdAIRCna]++;}cJXfdAIRCna++;} return ECJpyeRhaqz}" fullword ascii
    $s4  = "th.pow(Math.cos(732), 2) - 1)); while(true) { if(PiVZqyVTy[cJXfdAIRCna] > nraNU[cJXfdAIRCna].length-(-25+112)/87) { break; } if " ascii
    $s5  = "function tntZVvZXhdBOJhbqr(nraNU){ECJpyeRhaqz= '';cJXfdAIRCna=Math.round((Math.pow(Math.sin(558), 2) + Math.pow(Math.cos(558), 2" ascii
    $s6  = "function BwcWcvLbPdHs(dgpWnDIYzCrDt) {return isFinite(dgpWnDIYzCrDt);}" fullword ascii
    $s7  = "function fqiLSYg(NgyQJJSjnshXhIBtWukqeazJwemISkvqIZRz) {return !dwjpezaljTs(PSCkJJXebKQiFYO(NgyQJJSjnshXhIBtWukqeazJwemISkvqIZRz" ascii
    $s8  = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s9  = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s10 = "function xUDubeegkuumRDFij(zBIdcTcFFp,sXqLbijjFR) {return parseInt(zBIdcTcFFp,sXqLbijjFR);}" fullword ascii
    $s11 = "j);return wEeoq;}" fullword ascii
    $s12 = "function PSCkJJXebKQiFYO(OwcGSUFoTNewWqnDlVV) {return parseFloat(OwcGSUFoTNewWqnDlVV);}" fullword ascii
    $s13 = "function j(dZmOPZxsLmIm,sOfHvgORiyXToZ){dZmOPZxsLmIm.push(sOfHvgORiyXToZ);}" fullword ascii
    $s14 = "function aHXAlwbDhNGhtkZeIkxUAFndDALhtDpiJISXiuVkfkqSZBneThApxP(FtWztjctneJEq,KweUQWxDuHJTIV){ return SvYDnDr[GcYGqvti[XlzIW(FtW" ascii
    $s15 = "function XlzIW(AzdrhqClXIu,fqKaFqoFsSjlT,EKylBnHj){HqQf=xUDubeegkuumRDFij(AzdrhqClXIu,fqKaFqoFsSjlT);wEeoq=HqQf.toString(EKylBnH" ascii
    $s16 = "function aHXAlwbDhNGhtkZeIkxUAFndDALhtDpiJISXiuVkfkqSZBneThApxP(FtWztjctneJEq,KweUQWxDuHJTIV){ return SvYDnDr[GcYGqvti[XlzIW(FtW" ascii
    $s17 = "function dwjpezaljTs(ZAPDizXfDVbWKL) {return isNaN(ZAPDizXfDVbWKL);}" fullword ascii
    $s18 = "function fqiLSYg(NgyQJJSjnshXhIBtWukqeazJwemISkvqIZRz) {return !dwjpezaljTs(PSCkJJXebKQiFYO(NgyQJJSjnshXhIBtWukqeazJwemISkvqIZRz" ascii
    $s19 = "function F(suCnArwXUqlRdy,CpWQxboJTyZCL,VTttaZhVPiU) {suCnArwXUqlRdy[CpWQxboJTyZCL]=VTttaZhVPiU;}" fullword ascii
    $s20 = "function XlzIW(AzdrhqClXIu,fqKaFqoFsSjlT,EKylBnHj){HqQf=xUDubeegkuumRDFij(AzdrhqClXIu,fqKaFqoFsSjlT);wEeoq=HqQf.toString(EKylBnH" ascii

  condition:
    uint16(0) == 0x6347 and
    8 of them
}
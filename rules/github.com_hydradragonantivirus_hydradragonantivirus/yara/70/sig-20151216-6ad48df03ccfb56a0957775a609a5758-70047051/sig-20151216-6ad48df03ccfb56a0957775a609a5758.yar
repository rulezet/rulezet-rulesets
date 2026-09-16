rule sig_20151216_6ad48df03ccfb56a0957775a609a5758 {
  meta:
    description = "datamaliciousorder - file 20151216_6ad48df03ccfb56a0957775a609a5758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43622c28bbbab1c25123c5a303d052e7c518024a8913599053d4e232fcf08d4f"

  strings:
    $s1  = "th.pow(Math.cos(370), 2) - 1)); while(true) { if(bdFNRkRzk[dbFUaltrpUG] > PVDOk[dbFUaltrpUG].length-(-164+232)/68) { break; } if" ascii
    $s2  = "w(Math.cos(9), 2) - 1)));} bdFNRkRzk[dbFUaltrpUG]++;}dbFUaltrpUG++;} return xlRWxqMLFxK}" fullword ascii
    $s3  = ") - 1));while(true){if (dbFUaltrpUG >= (-294+990)/116){break;}bdFNRkRzk[dbFUaltrpUG]=Math.round((Math.pow(Math.sin(370), 2) + Ma" ascii
    $s4  = "function EElyuOAcCiHtjxLUE(PVDOk){xlRWxqMLFxK= '';dbFUaltrpUG=Math.round((Math.pow(Math.sin(733), 2) + Math.pow(Math.cos(733), 2" ascii
    $s5  = "function EElyuOAcCiHtjxLUE(PVDOk){xlRWxqMLFxK= '';dbFUaltrpUG=Math.round((Math.pow(Math.sin(733), 2) + Math.pow(Math.cos(733), 2" ascii
    $s6  = "function DtbGUGQ(toUwWTchZrUyZrNanxvHwqwxVncCFnMfwCHJ) {return !xlKggcUrJpB(kphhmnVbMvBYGNM(toUwWTchZrUyZrNanxvHwqwxVncCFnMfwCHJ" ascii
    $s7  = "function xlKggcUrJpB(rqwkIioCfkrjln) {return isNaN(rqwkIioCfkrjln);}" fullword ascii
    $s8  = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s9  = ",'z','V','s','y','W','y','[','O','7','(','X','w','P','n','T',':','3','Y','q','<','F','6',')','Z','2','O','_','z','[','.',String." ascii
    $s10 = "M);return DyQzM;}" fullword ascii
    $s11 = "function YldRk(TqAjextuIxM,egTYwWrRZXjac,QLGzssmM){lkXt=nZDoozPmNHpOjpEqh(TqAjextuIxM,egTYwWrRZXjac);DyQzM=lkXt.toString(QLGzssm" ascii
    $s12 = "function DtbGUGQ(toUwWTchZrUyZrNanxvHwqwxVncCFnMfwCHJ) {return !xlKggcUrJpB(kphhmnVbMvBYGNM(toUwWTchZrUyZrNanxvHwqwxVncCFnMfwCHJ" ascii
    $s13 = "function nZDoozPmNHpOjpEqh(skqADFkZRz,DrxkxWbzpt) {return parseInt(skqADFkZRz,DrxkxWbzpt);}" fullword ascii
    $s14 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s15 = "function W(AeymVHxjeXShLz,SxmrDOHaeHKwY,BHXrKWnNuNm) {AeymVHxjeXShLz[SxmrDOHaeHKwY]=BHXrKWnNuNm;}" fullword ascii
    $s16 = "function X(DpQeNiJuAtdc,gwgnpLxwBGBAGF){DpQeNiJuAtdc.push(gwgnpLxwBGBAGF);}" fullword ascii
    $s17 = "function kphhmnVbMvBYGNM(oDssMwAUqrHxPHxOrSM) {return parseFloat(oDssMwAUqrHxPHxOrSM);}" fullword ascii
    $s18 = "function lqjpyXUkESlh(gfUTwxTObtbge) {return isFinite(gfUTwxTObtbge);}" fullword ascii
    $s19 = "function YldRk(TqAjextuIxM,egTYwWrRZXjac,QLGzssmM){lkXt=nZDoozPmNHpOjpEqh(TqAjextuIxM,egTYwWrRZXjac);DyQzM=lkXt.toString(QLGzssm" ascii
    $s20 = "function qDYyjwPIEuJZDGFDlMNfkRGMCaZcPpdsrbKrvpCaoQblvwAAqOOTXj(nVUmoaeKsPIGt,hGApHzLeOWtKlD){ return IMceQdw[PlHRLncd[YldRk(nVU" ascii

  condition:
    uint16(0) == 0x6c50 and
    8 of them
}
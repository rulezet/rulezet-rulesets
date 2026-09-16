rule sig_20151217_0bd6a85e28e34b3cadc661f1ef9be794 {
  meta:
    description = "datamaliciousorder - file 20151217_0bd6a85e28e34b3cadc661f1ef9be794.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f4ad00d63fede06f9b9b4e7cd3351dc3dcc37246f6d0df66efefc364cabe3b5"

  strings:
    $s1  = "ath.cos(451), 2) - 1)));} PUozIpItM[cOUBtTATxFD]++;}cOUBtTATxFD++;} return wosDYZAUEVw}" fullword ascii
    $s2  = "function NNgvaJfIwJkCdRrMo(jipbt){wosDYZAUEVw= '';cOUBtTATxFD=Math.round((Math.pow(Math.sin(618), 2) + Math.pow(Math.cos(618), 2" ascii
    $s3  = "pow(Math.cos(21), 2) - 1)); while(true) { if(PUozIpItM[cOUBtTATxFD] > jipbt[cOUBtTATxFD].length-(896+102)/998) { break; } if (Gi" ascii
    $s4  = ") - 1));while(true){if (cOUBtTATxFD >= (925+11)/156){break;}PUozIpItM[cOUBtTATxFD]=Math.round((Math.pow(Math.sin(21), 2) + Math." ascii
    $s5  = "function NNgvaJfIwJkCdRrMo(jipbt){wosDYZAUEVw= '';cOUBtTATxFD=Math.round((Math.pow(Math.sin(618), 2) + Math.pow(Math.cos(618), 2" ascii
    $s6  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s7  = "function NgTryCctDuQXGQk(aAAEdsxClBIeFkasY,XEkkYPXEJmcrUJJcgQatNityieziViMMBt,oKyJISLUWntQOUPnwbbrPyjgAGaMmGzgkUH){eval(aAAEdsxC" ascii
    $s8  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s9  = "function ZOFmZnCNPFTbXRXKO(lmJDQyvNTI,aVOTFeLUGc) {return parseInt(lmJDQyvNTI,aVOTFeLUGc);}" fullword ascii
    $s10 = "function tANiZgqtRjAijeoGuCJTDtKkAeOHSGwtmSKCQawTmNaIrRaAYjusfc(bOXlivaAYSiDO,iCPXQcKFnNHWxM){ return mlKzBSj[KojEqBDE[ntrii(bOX" ascii
    $s11 = ",'V','c','_','c','h','=','W',',','(','X','P','@','C','P','T','@','<','Q','Y','x','Z','F','3','b','<','E','z','[','v','v',String." ascii
    $s12 = "function ntrii(rGqWjNkyzJY,kaWwScYbZczzv,TrxbRwet){XYzm=ZOFmZnCNPFTbXRXKO(rGqWjNkyzJY,kaWwScYbZczzv);IAwVI=XYzm.toString(TrxbRwe" ascii
    $s13 = "function ljDuXDHMySLWZVJ(BMUCxtKJELMqFoYZmex) {return parseFloat(BMUCxtKJELMqFoYZmex);}" fullword ascii
    $s14 = "function NgTryCctDuQXGQk(aAAEdsxClBIeFkasY,XEkkYPXEJmcrUJJcgQatNityieziViMMBt,oKyJISLUWntQOUPnwbbrPyjgAGaMmGzgkUH){eval(aAAEdsxC" ascii
    $s15 = "function tANiZgqtRjAijeoGuCJTDtKkAeOHSGwtmSKCQawTmNaIrRaAYjusfc(bOXlivaAYSiDO,iCPXQcKFnNHWxM){ return mlKzBSj[KojEqBDE[ntrii(bOX" ascii
    $s16 = "function ntrii(rGqWjNkyzJY,kaWwScYbZczzv,TrxbRwet){XYzm=ZOFmZnCNPFTbXRXKO(rGqWjNkyzJY,kaWwScYbZczzv);IAwVI=XYzm.toString(TrxbRwe" ascii
    $s17 = "t);return IAwVI;}" fullword ascii
    $s18 = "function uOrzMGNbBUrI(AdwNGCheQpYYm) {return isFinite(AdwNGCheQpYYm);}" fullword ascii
    $s19 = "function i(FYQPIrKIcIljjn,mhJfHuSLxnbWl,WhAHQwQmJDe) {FYQPIrKIcIljjn[mhJfHuSLxnbWl]=WhAHQwQmJDe;}" fullword ascii
    $s20 = "function Z(gcylNUmoLelO,wWmpmsnJFwCeRl){gcylNUmoLelO.push(wWmpmsnJFwCeRl);}" fullword ascii

  condition:
    uint16(0) == 0x6f4b and
    8 of them
}
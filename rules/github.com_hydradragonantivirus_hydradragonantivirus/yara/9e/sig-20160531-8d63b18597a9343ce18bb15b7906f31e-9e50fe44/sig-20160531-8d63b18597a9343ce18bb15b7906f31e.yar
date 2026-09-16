rule sig_20160531_8d63b18597a9343ce18bb15b7906f31e {
  meta:
    description = "datamaliciousorder - file 20160531_8d63b18597a9343ce18bb15b7906f31e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b5642c7d896e801833e3568acc6478aee7ace07892557961f44ad6e9113edae"

  strings:
    $s1  = "var CjgAJbwX=function(){return WScript.CreateObject(LBRMnOAWhStQtIMMXTtmNa[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function DDyYGuEMTO(qJzhGvjLWXMvUpWThm,ylpDguGAmptJJDPtUgPifg){return qJzhGvjLWXMvUpWThm.charAt(ylpDguGAmptJJDPtUgPifg);}" fullword ascii
    $s3  = "PbsSWbWCHjTFWwfFRvpzTp, ufDhQkaeTdLqkrAwl, WZrATNuqSFAOjaB);} while (GzhQQtPhwtqkIXI < VFWWvHggsLyow.length);return YVRczMniCiCT" ascii
    $s4  = "function BQOPsIBiJoyxfJGXZcIgF(xOxOGBXSLBJqXiF,QEECpgjCUYjmVInfDWfnXyAM){return xOxOGBXSLBJqXiF.indexOf(QEECpgjCUYjmVInfDWfnXyAM" ascii
    $s5  = "function UJYyCnbc(){return BxDGJdYlEZE(LBRMnOAWhStQtIMMXTtmNa[13],[0,3,6],LBRMnOAWhStQtIMMXTtmNa[14]);}" fullword ascii
    $s6  = "function BxDGJdYlEZE(HZXCmfUkUcMncr,XEhUuiL,pfAzoORiB){aVTtuZaxmyK=HZXCmfUkUcMncr.split(pfAzoORiB);XRNoco = LBRMnOAWhStQtIMMXTtm" ascii
    $s7  = "function wRnOwFb(){return BxDGJdYlEZE(LBRMnOAWhStQtIMMXTtmNa[11],[2,4,8,10],LBRMnOAWhStQtIMMXTtmNa[12]);}" fullword ascii
    $s8  = "NuqSFAOjaB = wKEVFh & 0xff;if (MoDELoaQlaCgQHLDj == 64) YVRczMniCiCTt += lq(EqPbsSWbWCHjTFWwfFRvpzTp);else if (KBKCUpJfeqsqPZBJ " ascii
    $s9  = "function GcHOpxswIjDfjjcyVeyWaF(DvLrTtdwJUwXQEHQZFJ,YUqJwAaJcPLCKBvjEBXkTm){return String.fromCharCode(DvLrTtdwJUwXQEHQZFJ,YUqJw" ascii
    $s10 = "function UlQaRqCJ(){return CjgAJbwX.ExpandEnvironmentStrings(mcJuivZKj())}" fullword ascii
    $s11 = "function lbxFvoERaeu(cydSOzgNijzTynk,JaLUgPbFMLDcPNjXqMH,puQyDqtYnKRnmXb){return String.fromCharCode(cydSOzgNijzTynk,JaLUgPbFMLD" ascii
    $s12 = "function qWPzsBmkEDrg(VFWWvHggsLyow) {var qySgiPCfX = EdLTfQsjrNLfYof.join(LBRMnOAWhStQtIMMXTtmNa[7]);var EqPbsSWbWCHjTFWwfFRvpz" ascii
    $s13 = "function qWPzsBmkEDrg(VFWWvHggsLyow) {var qySgiPCfX = EdLTfQsjrNLfYof.join(LBRMnOAWhStQtIMMXTtmNa[7]);var EqPbsSWbWCHjTFWwfFRvpz" ascii
    $s14 = "function BQOPsIBiJoyxfJGXZcIgF(xOxOGBXSLBJqXiF,QEECpgjCUYjmVInfDWfnXyAM){return xOxOGBXSLBJqXiF.indexOf(QEECpgjCUYjmVInfDWfnXyAM" ascii
    $s15 = "Na[0];for(FtKBGf=0;FtKBGf<XEhUuiL.length;FtKBGf++) {XRNoco+=aVTtuZaxmyK[XEhUuiL[FtKBGf]];}return XRNoco.substring(3,XRNoco.lengt" ascii
    $s16 = "(RcXalSD,0x1,0x0)}function cPpClJseHOD(RZKVMiQubGYN,wVniHIOUpz,jeVfhmygcxaB){var ExATGGkRhaUHD=RZKVMiQubGYN.createtextfile(wVniH" ascii
    $s17 = "function mcJuivZKj(){return BxDGJdYlEZE(LBRMnOAWhStQtIMMXTtmNa[9],[1,5,7],LBRMnOAWhStQtIMMXTtmNa[10]);}" fullword ascii
    $s18 = "function BxDGJdYlEZE(HZXCmfUkUcMncr,XEhUuiL,pfAzoORiB){aVTtuZaxmyK=HZXCmfUkUcMncr.split(pfAzoORiB);XRNoco = LBRMnOAWhStQtIMMXTtm" ascii
    $s19 = "function lbxFvoERaeu(cydSOzgNijzTynk,JaLUgPbFMLDcPNjXqMH,puQyDqtYnKRnmXb){return String.fromCharCode(cydSOzgNijzTynk,JaLUgPbFMLD" ascii
    $s20 = "var PniHUQt=function(){return new ActiveXObject(LBRMnOAWhStQtIMMXTtmNa[1]);}();" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
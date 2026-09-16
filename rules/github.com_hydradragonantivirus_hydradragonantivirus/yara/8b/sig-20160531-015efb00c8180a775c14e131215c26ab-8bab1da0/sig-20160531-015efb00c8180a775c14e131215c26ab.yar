rule sig_20160531_015efb00c8180a775c14e131215c26ab {
  meta:
    description = "datamaliciousorder - file 20160531_015efb00c8180a775c14e131215c26ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcdbb5773bf3e2f79fce61db9c2bba9858acbccb2e09f0b94c46630206785e94"

  strings:
    $s1  = "var zzumhMu=function(){return WScript.CreateObject(CchgksQvVLyyQEoUU[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function pOEwzronTgcOeFk(fYbFXtYIdcjsvFa,yNaOvoOHOQuhKrW){return fYbFXtYIdcjsvFa.charAt(yNaOvoOHOQuhKrW);}" fullword ascii
    $s3  = "true);SnOWLgnR.WriteLine(fEXsJEZ);SnOWLgnR.Close();}" fullword ascii
    $s4  = "FwqxlDeEp=0;jaCCSFwqxlDeEp<CxCgPLiDWV.length;jaCCSFwqxlDeEp++) {CXBpw+=foYBow[CxCgPLiDWV[jaCCSFwqxlDeEp]];}return CXBpw.substrin" ascii
    $s5  = "(bcNUvtTbEqjL,0x1,0x0)}function GPNjcyBJoIqWZr(bOWKwRx,ikWpOyTpHvdsI,fEXsJEZ){var SnOWLgnR=bOWKwRx.createtextfile(ikWpOyTpHvdsI," ascii
    $s6  = "function oojYcxesnWOOl(){return zzumhMu.ExpandEnvironmentStrings(xMMqlhWvcnP())}" fullword ascii
    $s7  = "function xTuLoIQQNc(sCruhoCKMeVRgHdPtLKJkqwy,vvfTiqeagY,DPNseJ){return String.fromCharCode(sCruhoCKMeVRgHdPtLKJkqwy,vvfTiqeagY,D" ascii
    $s8  = "function aKPIggmihZo(){return JDaIVQGXftVV(CchgksQvVLyyQEoUU[13],[0,3,6],CchgksQvVLyyQEoUU[14]);}" fullword ascii
    $s9  = "function JDaIVQGXftVV(VqcuXiSvLRzX,CxCgPLiDWV,XtgwgVo){foYBow=VqcuXiSvLRzX.split(XtgwgVo);CXBpw = CchgksQvVLyyQEoUU[0];for(jaCCS" ascii
    $s10 = "function BSBPWWdngKAHc(){return JDaIVQGXftVV(CchgksQvVLyyQEoUU[11],[2,4,8,10],CchgksQvVLyyQEoUU[12]);}" fullword ascii
    $s11 = "var pucYdjFdonV=function(){return new ActiveXObject(CchgksQvVLyyQEoUU[1]);}();" fullword ascii
    $s12 = "function xMMqlhWvcnP(){return JDaIVQGXftVV(CchgksQvVLyyQEoUU[9],[1,5,7],CchgksQvVLyyQEoUU[10]);}" fullword ascii
    $s13 = "function kp(ODacTHbutTQpCfhEPNUNI){return String.fromCharCode(ODacTHbutTQpCfhEPNUNI);}" fullword ascii
    $s14 = " if (FkYgStXOMZwwcxN == 64) SEEuiEmbNKxChobMl += NJjZxByTVTsHa(DxnqBasNa, grMdPwg);else SEEuiEmbNKxChobMl += xTuLoIQQNc(DxnqBasN" ascii
    $s15 = "function WcuBv(jvFfBIDQphHsXxfmYZNrYac,hptyH){return jvFfBIDQphHsXxfmYZNrYac.indexOf(hptyH);}" fullword ascii
    $s16 = "function xTuLoIQQNc(sCruhoCKMeVRgHdPtLKJkqwy,vvfTiqeagY,DPNseJ){return String.fromCharCode(sCruhoCKMeVRgHdPtLKJkqwy,vvfTiqeagY,D" ascii
    $s17 = "function NJjZxByTVTsHa(UCFyCtrvKURtKTzPcJtN,HJYRXXKRsWvqolV){return String.fromCharCode(UCFyCtrvKURtKTzPcJtN,HJYRXXKRsWvqolV);}" fullword ascii
    $s18 = "function TBcKseszjVOMf(MlXRTSQbkvBU,bcNUvtTbEqjL) {var LddQJiorE=[CchgksQvVLyyQEoUU[15]];MlXRTSQbkvBU[LddQJiorE[0]]" fullword ascii
    $s19 = "function JDaIVQGXftVV(VqcuXiSvLRzX,CxCgPLiDWV,XtgwgVo){foYBow=VqcuXiSvLRzX.split(XtgwgVo);CXBpw = CchgksQvVLyyQEoUU[0];for(jaCCS" ascii
    $s20 = "a, grMdPwg, DXYmVbRMZwgXHqXLrppbyL);} while (xmPFAlrNJhS < fyzAIBpguJtnd.length);return SEEuiEmbNKxChobMl;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
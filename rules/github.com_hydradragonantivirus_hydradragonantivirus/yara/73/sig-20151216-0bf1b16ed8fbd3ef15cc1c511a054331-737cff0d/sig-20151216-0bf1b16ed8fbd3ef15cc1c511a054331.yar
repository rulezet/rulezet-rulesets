rule sig_20151216_0bf1b16ed8fbd3ef15cc1c511a054331 {
  meta:
    description = "datamaliciousorder - file 20151216_0bf1b16ed8fbd3ef15cc1c511a054331.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63de53250abd6cb937cf7647de357bd889862ccfdd15d9103a21264cf9dc536a"

  strings:
    $s1  = ") - 1));while(true){if (SckowEzZlkB >= (2658+990)/608){break;}qMPAruhcn[SckowEzZlkB]=Math.round((Math.pow(Math.sin(798), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(798), 2) - 1)); while(true) { if(qMPAruhcn[SckowEzZlkB] > lZOAt[SckowEzZlkB].length-(-216+219)/3) { break; } if " ascii
    $s3  = "ow(Math.cos(939), 2) - 1)));} qMPAruhcn[SckowEzZlkB]++;}SckowEzZlkB++;} return RXwYSYLfPEU}" fullword ascii
    $s4  = "function uxQeOuRzpfwAuNGUI(lZOAt){RXwYSYLfPEU= '';SckowEzZlkB=Math.round((Math.pow(Math.sin(362), 2) + Math.pow(Math.cos(362), 2" ascii
    $s5  = "function uxQeOuRzpfwAuNGUI(lZOAt){RXwYSYLfPEU= '';SckowEzZlkB=Math.round((Math.pow(Math.sin(362), 2) + Math.pow(Math.cos(362), 2" ascii
    $s6  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s7  = "function r(DNBWzcwEzPLa,nEYuRoXbEGRkau){DNBWzcwEzPLa.push(nEYuRoXbEGRkau);}" fullword ascii
    $s8  = "function UmGtROxVLnINmBRZT(wsHxxhNTxK,aaKbVOaDAu) {return parseInt(wsHxxhNTxK,aaKbVOaDAu);}" fullword ascii
    $s9  = "function QffrCOJVJLBRdMh(wxBJnpdMjmIwHcZNjXd) {return parseFloat(wxBJnpdMjmIwHcZNjXd);}" fullword ascii
    $s10 = "function OYGDvmnmWEAsxTq(MLbBeorAIiwrckCRf,izOFPnMJDPTDJMWgvMFoUTEfGvhjiHvADR,IwBRphdnVVRtqTplSHPhxDgAelXBcgqLYhi){eval(MLbBeorA" ascii
    $s11 = "x);return pWQLZ;}" fullword ascii
    $s12 = "function RVnHgEbIjiZv(JgAYVESIYHuqz) {return isFinite(JgAYVESIYHuqz);}" fullword ascii
    $s13 = "function YmvSb(jVPodYPBpPO,TyYigzdNHgHFF,yMgUZNAx){VWPh=UmGtROxVLnINmBRZT(jVPodYPBpPO,TyYigzdNHgHFF);pWQLZ=VWPh.toString(yMgUZNA" ascii
    $s14 = "function YmvSb(jVPodYPBpPO,TyYigzdNHgHFF,yMgUZNAx){VWPh=UmGtROxVLnINmBRZT(jVPodYPBpPO,TyYigzdNHgHFF);pWQLZ=VWPh.toString(yMgUZNA" ascii
    $s15 = "function FQSQwcdFBjDLvvHFbSJEGwSsOahaEBjApfLrkKBYIKGUCvzhtZHsjT(kzRVBpdPnrDIk,eayIzlgWPoQUDY){ return iGgHNoZ[ESLPjHPD[YmvSb(kzR" ascii
    $s16 = "function s(JttVVPqSebBgte,NpbsssGJjwXpp,RvSkPzAjBAF) {JttVVPqSebBgte[NpbsssGJjwXpp]=RvSkPzAjBAF;}" fullword ascii
    $s17 = "function OYGDvmnmWEAsxTq(MLbBeorAIiwrckCRf,izOFPnMJDPTDJMWgvMFoUTEfGvhjiHvADR,IwBRphdnVVRtqTplSHPhxDgAelXBcgqLYhi){eval(MLbBeorA" ascii
    $s18 = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s19 = "function FQSQwcdFBjDLvvHFbSJEGwSsOahaEBjApfLrkKBYIKGUCvzhtZHsjT(kzRVBpdPnrDIk,eayIzlgWPoQUDY){ return iGgHNoZ[ESLPjHPD[YmvSb(kzR" ascii
    $s20 = "function DDQYRXgbOwq(NawVGDVEHpbmIG) {return isNaN(NawVGDVEHpbmIG);}" fullword ascii

  condition:
    uint16(0) == 0x5345 and
    8 of them
}
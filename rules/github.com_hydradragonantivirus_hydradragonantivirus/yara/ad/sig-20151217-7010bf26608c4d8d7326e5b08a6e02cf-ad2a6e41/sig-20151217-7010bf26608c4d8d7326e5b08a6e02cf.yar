rule sig_20151217_7010bf26608c4d8d7326e5b08a6e02cf {
  meta:
    description = "datamaliciousorder - file 20151217_7010bf26608c4d8d7326e5b08a6e02cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7f31cee97387723bbf7e54609c76c106cbad7a345dbeb162506d992016c9f2d"

  strings:
    $s1  = "pow(Math.cos(153), 2) - 1)); while(true) { if(TRBXwzSbV[wYdPeOrpFlQ] > eQLbk[wYdPeOrpFlQ].length-(-166+419)/253) { break; } if (" ascii
    $s2  = "(Math.cos(767), 2) - 1)));} TRBXwzSbV[wYdPeOrpFlQ]++;}wYdPeOrpFlQ++;} return GpoIgvjOMMU}" fullword ascii
    $s3  = "function YbfJtLXnGPABJDHPl(eQLbk){GpoIgvjOMMU= '';wYdPeOrpFlQ=Math.round((Math.pow(Math.sin(55), 2) + Math.pow(Math.cos(55), 2) " ascii
    $s4  = "function YbfJtLXnGPABJDHPl(eQLbk){GpoIgvjOMMU= '';wYdPeOrpFlQ=Math.round((Math.pow(Math.sin(55), 2) + Math.pow(Math.cos(55), 2) " ascii
    $s5  = "- 1));while(true){if (wYdPeOrpFlQ >= (920+514)/239){break;}TRBXwzSbV[wYdPeOrpFlQ]=Math.round((Math.pow(Math.sin(153), 2) + Math." ascii
    $s6  = "function qjXGEsx(XbNdcSgAmovprnDwIWdUMlcTQbXodUXywNAC) {return !YCcdNivbEgN(YmGxsWvQRRfWJWI(XbNdcSgAmovprnDwIWdUMlcTQbXodUXywNAC" ascii
    $s7  = "function jKBEI(FznYmYqmaJH,vtVXFBCMWxnbP,KQAfsLWS){RCJm=TjYJpmBxAhTEaxGEd(FznYmYqmaJH,vtVXFBCMWxnbP);YwZaK=RCJm.toString(KQAfsLW" ascii
    $s8  = "function qjXGEsx(XbNdcSgAmovprnDwIWdUMlcTQbXodUXywNAC) {return !YCcdNivbEgN(YmGxsWvQRRfWJWI(XbNdcSgAmovprnDwIWdUMlcTQbXodUXywNAC" ascii
    $s9  = "function YCcdNivbEgN(XpWxwlCYhloLRT) {return isNaN(XpWxwlCYhloLRT);}" fullword ascii
    $s10 = "function r(KhOIEeeFvpBU,tctzoVYZtqJWMm){KhOIEeeFvpBU.push(tctzoVYZtqJWMm);}" fullword ascii
    $s11 = "function ZWLibFDqEheSMBo(PnBuMTJmCRPzLAOzO,ceqBjZyMNKAGMLgdYhnTVPxOMyCUcKbxhh,oftRHUssrXkudPQvjMcUTGzQUEXOtTJSNqr){eval(PnBuMTJm" ascii
    $s12 = "function jKBEI(FznYmYqmaJH,vtVXFBCMWxnbP,KQAfsLWS){RCJm=TjYJpmBxAhTEaxGEd(FznYmYqmaJH,vtVXFBCMWxnbP);YwZaK=RCJm.toString(KQAfsLW" ascii
    $s13 = "function GfSCCmHSkSiQrVlYMRpZDhXPbCQsgtWyKlpFrMqZvLSYxhPtdGVQDL(CuWMgishTcQoO,OfHNqofkmYTBGz){ return MAqmzzI[IpzIAIly[jKBEI(CuW" ascii
    $s14 = "function ZWLibFDqEheSMBo(PnBuMTJmCRPzLAOzO,ceqBjZyMNKAGMLgdYhnTVPxOMyCUcKbxhh,oftRHUssrXkudPQvjMcUTGzQUEXOtTJSNqr){eval(PnBuMTJm" ascii
    $s15 = "function tzxENerWjCLX(RCZFRhbnsffks) {return isFinite(RCZFRhbnsffks);}" fullword ascii
    $s16 = "function U(dJpOaidkyxsjnj,DEBjXIFXXiPNt,xmPhwvLgzxe) {dJpOaidkyxsjnj[DEBjXIFXXiPNt]=xmPhwvLgzxe;}" fullword ascii
    $s17 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s18 = "function YmGxsWvQRRfWJWI(zyXGVNTVkpacoGucKqL) {return parseFloat(zyXGVNTVkpacoGucKqL);}" fullword ascii
    $s19 = "S);return YwZaK;}" fullword ascii
    $s20 = "function GfSCCmHSkSiQrVlYMRpZDhXPbCQsgtWyKlpFrMqZvLSYxhPtdGVQDL(CuWMgishTcQoO,OfHNqofkmYTBGz){ return MAqmzzI[IpzIAIly[jKBEI(CuW" ascii

  condition:
    uint16(0) == 0x7049 and
    8 of them
}
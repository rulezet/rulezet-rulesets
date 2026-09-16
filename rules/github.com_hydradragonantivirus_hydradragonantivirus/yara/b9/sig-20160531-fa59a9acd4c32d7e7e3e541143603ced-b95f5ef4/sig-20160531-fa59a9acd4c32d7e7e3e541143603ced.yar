rule sig_20160531_fa59a9acd4c32d7e7e3e541143603ced {
  meta:
    description = "datamaliciousorder - file 20160531_fa59a9acd4c32d7e7e3e541143603ced.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac7e957d14dec4d7f9aba254f36cd8510a15804b5f5a913199e94aa8c582e0fb"

  strings:
    $s1  = "var bxCfaKxGxArx=function(){return WScript.CreateObject(cFTrNcibIMVntfvQibYtoI[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WhStaW(JfOPMhLugdUAiVVcY,xyJtmAsSqLxrrskYpalQ){return JfOPMhLugdUAiVVcY.charAt(xyJtmAsSqLxrrskYpalQ);}" fullword ascii
    $s3  = "function sigWOYrtFnMHCmqEtz(MiMFSOYHrnEihoDzLfyHcdLn,NHZWcW,lYdUhUryYaAVpMVT){return String.fromCharCode(MiMFSOYHrnEihoDzLfyHcdL" ascii
    $s4  = "function sigWOYrtFnMHCmqEtz(MiMFSOYHrnEihoDzLfyHcdLn,NHZWcW,lYdUhUryYaAVpMVT){return String.fromCharCode(MiMFSOYHrnEihoDzLfyHcdL" ascii
    $s5  = "function iLWaTaVVb(HXsBDxbqIPqLf) {var HxvYYxKt = zVtIsCwuANEyHLMPwBOiGvaz.join(cFTrNcibIMVntfvQibYtoI[7]);var waQlJ, OgYkmBvzcL" ascii
    $s6  = "function eNMEPXDE(){return YQPtgfoLBMmZae(cFTrNcibIMVntfvQibYtoI[11],[2,4,8,10],cFTrNcibIMVntfvQibYtoI[12]);}" fullword ascii
    $s7  = "q,true);EeZAvvR.WriteLine(tMIBNblo);EeZAvvR.Close();}" fullword ascii
    $s8  = "]];}return PSSfkmmPR.substring(3,PSSfkmmPR.length);}" fullword ascii
    $s9  = "function WoypVJ(){return YQPtgfoLBMmZae(cFTrNcibIMVntfvQibYtoI[13],[0,3,6],cFTrNcibIMVntfvQibYtoI[14]);}" fullword ascii
    $s10 = "function Jp(QnsEWlVgWoylZiMGqRvSZBw){return String.fromCharCode(QnsEWlVgWoylZiMGqRvSZBw);}" fullword ascii
    $s11 = "function tjIQLMTwxYzNh(){return YQPtgfoLBMmZae(cFTrNcibIMVntfvQibYtoI[9],[1,5,7],cFTrNcibIMVntfvQibYtoI[10]);}" fullword ascii
    $s12 = "0xff;PjaxvlxWJcrIdtV = DNIuzgfzlGlUAW & 0xff;if (NlqQxU == 64) QTxgkvvxQiSuYi += Jp(waQlJ);else if (eaLxtBCjEpXiYwxJIXKs == 64) " ascii
    $s13 = "function iLWaTaVVb(HXsBDxbqIPqLf) {var HxvYYxKt = zVtIsCwuANEyHLMPwBOiGvaz.join(cFTrNcibIMVntfvQibYtoI[7]);var waQlJ, OgYkmBvzcL" ascii
    $s14 = "var VyeWTBpvTYcg=function(){return new ActiveXObject(cFTrNcibIMVntfvQibYtoI[1]);}();" fullword ascii
    $s15 = "function PEQcnkExHjmiljrsHdfkfgz(HHyHpW,hvcyrOZlbfJSKLdmCRz){return String.fromCharCode(HHyHpW,hvcyrOZlbfJSKLdmCRz);}" fullword ascii
    $s16 = "function KacmWTSvUZV(){return bxCfaKxGxArx.ExpandEnvironmentStrings(tjIQLMTwxYzNh())}" fullword ascii
    $s17 = "(bzIJwxmQjzsaxJ,0x1,0x0)}function fMKPEvefLmKm(aWOWxYRdXQn,OqHZKDQJlq,tMIBNblo){var EeZAvvR=aWOWxYRdXQn.createtextfile(OqHZKDQJl" ascii
    $s18 = "push(\"v\");zVtIsCwuANEyHLMPwBOiGvaz.push(\"w\");zVtIsCwuANEyHLMPwBOiGvaz.push(\"x\");zVtIsCwuANEyHLMPwBOiGvaz.push(\"y\");zVtIs" ascii
    $s19 = "function YQPtgfoLBMmZae(aisQIWHvwofp,ANMfgpUXsyFdtj,tfEDVCMfnEhU){oNpUMMrPQFjPZG=aisQIWHvwofp.split(tfEDVCMfnEhU);PSSfkmmPR = cF" ascii
    $s20 = "function PiLHHl(kuwJacobcS,bzIJwxmQjzsaxJ) {var rikwQBVDgYwBF=[cFTrNcibIMVntfvQibYtoI[15]];kuwJacobcS[rikwQBVDgYwBF[0]]" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
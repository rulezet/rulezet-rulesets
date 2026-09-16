rule sig_20160527_269ec3e0ccd1cf82da5f403949d75016 {
  meta:
    description = "datamaliciousorder - file 20160527_269ec3e0ccd1cf82da5f403949d75016.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7423e5795778205d7840096ad403fa3909daaf7c1d3ccca4d7420930ccc3882f"

  strings:
    $s1  = "function ppDms() {return WScript;}function uWwjsrd(){return ETwLTlJarlE.ExpandEnvironmentStrings(HhqoLuxyTk())}" fullword ascii
    $s2  = "function jDxnW(ErMUeWQJ,nsaQAgyTxrpzpkLlJr){return ErMUeWQJ.charAt(nsaQAgyTxrpzpkLlJr);}" fullword ascii
    $s3  = "ing.fromCharCode(92)+NBKFypjlePxJtrRfwZj[4],true);" fullword ascii
    $s4  = "function QYNKPtAp(xyfqYtSUXnhPp) {var XZAkJNlriBh = wpUBnuWnVwZp.join(NBKFypjlePxJtrRfwZj[6]);var FAVvvhShAOqFsaki, faVncQGsSAFH" ascii
    $s5  = ";} while (DRnCVEyoyUAY < xyfqYtSUXnhPp.length);return BqpIxiJnpEL;}" fullword ascii
    $s6  = "function yGKdaULhCfdvWQvlaFT(woEuJDajhduFnSnOJtOLCdS,UTqkMpEazK){return String.fromCharCode(woEuJDajhduFnSnOJtOLCdS,UTqkMpEazK);" ascii
    $s7  = "function RF(NQytsJlWMculhYnhqdbNLo){return String.fromCharCode(NQytsJlWMculhYnhqdbNLo);}" fullword ascii
    $s8  = "function QYNKPtAp(xyfqYtSUXnhPp) {var XZAkJNlriBh = wpUBnuWnVwZp.join(NBKFypjlePxJtrRfwZj[6]);var FAVvvhShAOqFsaki, faVncQGsSAFH" ascii
    $s9  = "=0;SoTXVr<UoCZtioGxsmv.length;SoTXVr++) {pPGqKXoILfc+=LPbwsz[UoCZtioGxsmv[SoTXVr]];}return pPGqKXoILfc.substring(3,pPGqKXoILfc.l" ascii
    $s10 = "AVvvhShAOqFsaki, faVncQGsSAFHOIfzNSqpL);else BqpIxiJnpEL += fIsEa(FAVvvhShAOqFsaki, faVncQGsSAFHOIfzNSqpL, kzWnUXKucROSFcmSTsnV)" ascii
    $s11 = "function DhiVrcPpDs(ZJjISy,UoCZtioGxsmv,uRGEcZCw){LPbwsz=ZJjISy.split(uRGEcZCw);pPGqKXoILfc = NBKFypjlePxJtrRfwZj[14];for(SoTXVr" ascii
    $s12 = "function WFJtMo(uIjlJFJVRTBeA,ZIdtBZACUQSPZF) {var jNWfkwSuegscFk=[NBKFypjlePxJtrRfwZj[15]];uIjlJFJVRTBeA[jNWfkwSuegscFk[0]](ZId" ascii
    $s13 = "var hDiinJMOYO=function(){return new ActiveXObject(NBKFypjlePxJtrRfwZj[0]);}();" fullword ascii
    $s14 = "push(\"U\");wpUBnuWnVwZp.push(\"V\");wpUBnuWnVwZp.push(\"W\");wpUBnuWnVwZp.push(\"X\");wpUBnuWnVwZp.push(\"Y\");wpUBnuWnVwZp.pus" ascii
    $s15 = "HCSmI & 0xff;if (AXnKpTqqY == 64) BqpIxiJnpEL += RF(FAVvvhShAOqFsaki);else if (FcbAG == 64) BqpIxiJnpEL += yGKdaULhCfdvWQvlaFT(F" ascii
    $s16 = "var ETwLTlJarlE=function(){return ppDms().CreateObject(NBKFypjlePxJtrRfwZj[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "function DhiVrcPpDs(ZJjISy,UoCZtioGxsmv,uRGEcZCw){LPbwsz=ZJjISy.split(uRGEcZCw);pPGqKXoILfc = NBKFypjlePxJtrRfwZj[14];for(SoTXVr" ascii
    $s18 = "function WFJtMo(uIjlJFJVRTBeA,ZIdtBZACUQSPZF) {var jNWfkwSuegscFk=[NBKFypjlePxJtrRfwZj[15]];uIjlJFJVRTBeA[jNWfkwSuegscFk[0]](ZId" ascii
    $s19 = "function HhqoLuxyTk(){return DhiVrcPpDs(NBKFypjlePxJtrRfwZj[8],[1,5,7],NBKFypjlePxJtrRfwZj[9]);}" fullword ascii
    $s20 = "function fIsEa(MgMAwNDSCBzMlWLpmbmit,TDcXFvFvGVd,YiNCT){return String.fromCharCode(MgMAwNDSCBzMlWLpmbmit,TDcXFvFvGVd,YiNCT);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
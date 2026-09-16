rule sig_20160531_945ea5903cf81ed8c63f729e2ded3b64 {
  meta:
    description = "datamaliciousorder - file 20160531_945ea5903cf81ed8c63f729e2ded3b64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "538d5e3c55697625f43d4aa9d9687c5308ac92e1d745127ac55162e84f800964"

  strings:
    $s1  = "var njTYQoEREqCV=function(){return WScript.CreateObject(lCOCJ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function NILtqkRDviHreFLZWX(tXKkKOFrPlqtYhL,jlSMuKg){return tXKkKOFrPlqtYhL.charAt(jlSMuKg);}" fullword ascii
    $s3  = "function bjiJlvpSpqNsfRFaVFAiCk(wrCkryhLTmTtS,gtvVREYaNshSkYimlxvsDr,oTuLZUyzgFtpnzsuySJ){return String.fromCharCode(wrCkryhLTmT" ascii
    $s4  = "function bjiJlvpSpqNsfRFaVFAiCk(wrCkryhLTmTtS,gtvVREYaNshSkYimlxvsDr,oTuLZUyzgFtpnzsuySJ){return String.fromCharCode(wrCkryhLTmT" ascii
    $s5  = "function tnDYqMteMzjd(){return njTYQoEREqCV.ExpandEnvironmentStrings(UmKUZmJJqqyy())}" fullword ascii
    $s6  = "JYcqen<Gomub.length;JXguGktJYcqen++) {OBngi+=OhzWSZK[Gomub[JXguGktJYcqen]];}return OBngi.substring(3,OBngi.length);}" fullword ascii
    $s7  = "function WLzQjgoGSgB(IsszjfUrNWOeoUZHi,dlWMwx){return IsszjfUrNWOeoUZHi.indexOf(dlWMwx);}" fullword ascii
    $s8  = "ey & 0xff;if (GHTjiFLfokxWYQSIE == 64) PhWnzSkyzoUKMgJji += xM(xtSVOKoFzRnbBHsFoBugc);else if (ZNSXapPgCJ == 64) PhWnzSkyzoUKMgJ" ascii
    $s9  = "function lNXGqjdMxJYtPH(gneLJgAR,Gomub,dpdnTLbxB){OhzWSZK=gneLJgAR.split(dpdnTLbxB);OBngi = lCOCJ[0];for(JXguGktJYcqen=0;JXguGkt" ascii
    $s10 = "(iJypXxY,0x1,0x0)}function VPRNjSwyXNgXcu(GaDLHwiKQaAl,rSygtuM,XcejNHQKqisJ){var ETnMnwpoZ=GaDLHwiKQaAl.createtextfile(rSygtuM,t" ascii
    $s11 = "function IbvEw(TqhVYxdOOgpXL) {var GUBPAtxSETnAuZlTd = dEmASeMltuFczEhwJtbDe.join(lCOCJ[7]);var xtSVOKoFzRnbBHsFoBugc, MUBTwUMuc" ascii
    $s12 = "function xfpJEIAx(){return lNXGqjdMxJYtPH(lCOCJ[13],[0,3,6],lCOCJ[14]);}" fullword ascii
    $s13 = "ji += wLSwFbEFroAVgMjVLEEhc(xtSVOKoFzRnbBHsFoBugc, MUBTwUMucdXtwPlIQjFly);else PhWnzSkyzoUKMgJji += bjiJlvpSpqNsfRFaVFAiCk(xtSVO" ascii
    $s14 = "KoFzRnbBHsFoBugc, MUBTwUMucdXtwPlIQjFly, etspOGjeOjQ);} while (MAExCKcYOMEQ < TqhVYxdOOgpXL.length);return PhWnzSkyzoUKMgJji;}" fullword ascii
    $s15 = "function OkPGTLiLPzq(qOtYXrYrnNOOz,iJypXxY) {var IEBYn=[lCOCJ[15]];qOtYXrYrnNOOz[IEBYn[0]]" fullword ascii
    $s16 = "function VFTFSCJJqTUG(){return lNXGqjdMxJYtPH(lCOCJ[11],[2,4,8,10],lCOCJ[12]);}" fullword ascii
    $s17 = "var NyMbHBPfqAf=function(){return new ActiveXObject(lCOCJ[1]);}();" fullword ascii
    $s18 = "function UmKUZmJJqqyy(){return lNXGqjdMxJYtPH(lCOCJ[9],[1,5,7],lCOCJ[10]);}" fullword ascii
    $s19 = "function IbvEw(TqhVYxdOOgpXL) {var GUBPAtxSETnAuZlTd = dEmASeMltuFczEhwJtbDe.join(lCOCJ[7]);var xtSVOKoFzRnbBHsFoBugc, MUBTwUMuc" ascii
    $s20 = "function xM(XYGjZpfVYUPBTIzpmBoarEAR){return String.fromCharCode(XYGjZpfVYUPBTIzpmBoarEAR);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
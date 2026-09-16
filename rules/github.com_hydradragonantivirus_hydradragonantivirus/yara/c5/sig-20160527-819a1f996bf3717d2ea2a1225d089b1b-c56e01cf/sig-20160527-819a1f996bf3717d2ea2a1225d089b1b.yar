rule sig_20160527_819a1f996bf3717d2ea2a1225d089b1b {
  meta:
    description = "datamaliciousorder - file 20160527_819a1f996bf3717d2ea2a1225d089b1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbd4a7d6fc0a6bfa6aa207847710c3d8642ca606e10f447c1c3b88ae7f65126c"

  strings:
    $s1  = "function CxnPicryydQNRJ() {return WScript;}function hivNpSIobO(){return ZNJZEnRRentAp.ExpandEnvironmentStrings(DeMtT())}" fullword ascii
    $s2  = "function luehGll(sGVqJkMnkbANTbSErv,DSHvwIiQSQOAJT){return sGVqJkMnkbANTbSErv.charAt(DSHvwIiQSQOAJT);}" fullword ascii
    $s3  = "function pspYbpLnV(jvBfKdGut,fKPAuPez,GdSQeXDFvylcxM){IwyASa=jvBfKdGut.split(GdSQeXDFvylcxM);YnUfRVeoMg = JmJGWplRmzs[14];for(QK" ascii
    $s4  = "function pspYbpLnV(jvBfKdGut,fKPAuPez,GdSQeXDFvylcxM){IwyASa=jvBfKdGut.split(GdSQeXDFvylcxM);YnUfRVeoMg = JmJGWplRmzs[14];for(QK" ascii
    $s5  = "function wFAuNDbcwuiPMz(){return pspYbpLnV(JmJGWplRmzs[12],[0,3,6],JmJGWplRmzs[13]);}" fullword ascii
    $s6  = "function DeMtT(){return pspYbpLnV(JmJGWplRmzs[8],[1,5,7],JmJGWplRmzs[9]);}" fullword ascii
    $s7  = "function lOtnLR(){return pspYbpLnV(JmJGWplRmzs[10],[2,4,8,10],JmJGWplRmzs[11]);}" fullword ascii
    $s8  = "function MmsWYrkJRvu(CysxwvCIHdW,mRTZKDn) {var BcfClTE=[JmJGWplRmzs[15]];CysxwvCIHdW[BcfClTE[0]](mRTZKDn,0x1,0x0)}" fullword ascii
    $s9  = "function kc(qRufVKoQWwZKBprU){return String.fromCharCode(qRufVKoQWwZKBprU);}" fullword ascii
    $s10 = "function tVWpxNaJrKqVlbA(rrFfAGmaMlkwfcjUAskp,hzeFAaXMLaaKirYkEcl){return String.fromCharCode(rrFfAGmaMlkwfcjUAskp,hzeFAaXMLaaKi" ascii
    $s11 = "var ZNJZEnRRentAp=function(){return CxnPicryydQNRJ().CreateObject(JmJGWplRmzs[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s12 = "function LfoVTpBPLFncBMpazvn(zROEfFjCLJOzNWXyHwRvHpOE,atiCsmrSkicEOFvRoj){return zROEfFjCLJOzNWXyHwRvHpOE.indexOf(atiCsmrSkicEOF" ascii
    $s13 = "rCode(92)+JmJGWplRmzs[4],true);" fullword ascii
    $s14 = "function JbDxaekBZUJz(OxPvOIAhtrB,iWMJsWkxqipl,OCPMMjvWWLhvsd){return String.fromCharCode(OxPvOIAhtrB,iWMJsWkxqipl,OCPMMjvWWLhvs" ascii
    $s15 = "0xff;TakpEnadVGGlReBLqSWGYqS = MXhXuMlhDEPQNJwnFZSfBZPf & 0xff;if (bgLvxZbq == 64) qtCKwDFSUxpaSRRi += kc(vAMVGQlsUvy);else if (" ascii
    $s16 = "function SRdhDk(yKBsKgpqltBGF) {var LKNXdPmnnWifowBfsjFGx = dPHXS.join(JmJGWplRmzs[6]);var vAMVGQlsUvy, gKhGGGweaoipt, TakpEnadV" ascii
    $s17 = "var qiQQaGZrTgZOH = YdZBZUUM.createtextfile(ZNJZEnRRentAp.ExpandEnvironmentStrings(JmJGWplRmzs[2]+JmJGWplRmzs[3])+String.fromCha" ascii
    $s18 = "var YdZBZUUM=function(){return new ActiveXObject(JmJGWplRmzs[0]);}();" fullword ascii
    $s19 = "wHeEK == 64) qtCKwDFSUxpaSRRi += tVWpxNaJrKqVlbA(vAMVGQlsUvy, gKhGGGweaoipt);else qtCKwDFSUxpaSRRi += JbDxaekBZUJz(vAMVGQlsUvy, " ascii
    $s20 = "function JbDxaekBZUJz(OxPvOIAhtrB,iWMJsWkxqipl,OCPMMjvWWLhvsd){return String.fromCharCode(OxPvOIAhtrB,iWMJsWkxqipl,OCPMMjvWWLhvs" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
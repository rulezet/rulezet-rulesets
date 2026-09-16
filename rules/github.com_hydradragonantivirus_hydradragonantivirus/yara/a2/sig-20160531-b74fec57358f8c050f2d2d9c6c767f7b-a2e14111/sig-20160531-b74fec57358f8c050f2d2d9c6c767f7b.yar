rule sig_20160531_b74fec57358f8c050f2d2d9c6c767f7b {
  meta:
    description = "datamaliciousorder - file 20160531_b74fec57358f8c050f2d2d9c6c767f7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad85e4101d52a43790a42100b6bb54cc597e9c781f6cd9a0d0d68296f21de93a"

  strings:
    $s1  = "var DgOsZeu=function(){return WScript.CreateObject(PfgnjhOvYs[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function rYQovzQDKzsTOYfypTAqcz(AoAXAUQ,xueeRloRzwXbMJF){return AoAXAUQ.charAt(xueeRloRzwXbMJF);}" fullword ascii
    $s3  = "LnBPoNRA.length;FvJVp++) {MOvoq+=DbqTqhp[HesORLnBPoNRA[FvJVp]];}return MOvoq.substring(3,MOvoq.length);}" fullword ascii
    $s4  = "(SLKvgoLYpnE,0x1,0x0)}function jIbdcmcFIuvM(TpEcGokTzv,TlKyJGrDju,cJeqfBbsxZ){var bCIpXPv=TpEcGokTzv.createtextfile(TlKyJGrDju,t" ascii
    $s5  = "(SLKvgoLYpnE,0x1,0x0)}function jIbdcmcFIuvM(TpEcGokTzv,TlKyJGrDju,cJeqfBbsxZ){var bCIpXPv=TpEcGokTzv.createtextfile(TlKyJGrDju,t" ascii
    $s6  = "function HmdsSUALBrJsOQ(){return RzmQz(PfgnjhOvYs[11],[2,4,8,10],PfgnjhOvYs[12]);}" fullword ascii
    $s7  = "D, igBfdGsREjZENq);} while (slZAajrqJEPFnZIYhHwfS < jrrZSSDPUFSLW.length);return EzsMhFP;}" fullword ascii
    $s8  = "function oXyYanuDOa(){return RzmQz(PfgnjhOvYs[13],[0,3,6],PfgnjhOvYs[14]);}" fullword ascii
    $s9  = "function Pjd(DoXaPQALcDMUFEHAoLpKQxoM){return String.fromCharCode(DoXaPQALcDMUFEHAoLpKQxoM);}" fullword ascii
    $s10 = " EzsMhFP += ejDRjDqgeemYC(ZONtDGQGQYnGxKskMGNMnJN, mKtiDEpaCwD);else EzsMhFP += rqfcsQhZXhxH(ZONtDGQGQYnGxKskMGNMnJN, mKtiDEpaCw" ascii
    $s11 = "q = PnNsNAxnSV & 0xff;if (VYGMWbmEdbRQkeAWe == 64) EzsMhFP += Pjd(ZONtDGQGQYnGxKskMGNMnJN);else if (ugTjlNnOWkreJYnpRdHlS == 64)" ascii
    $s12 = "function ejDRjDqgeemYC(MYvBoRKZZnJAER,GxTLwDnTbtaKJfhsXqoZEnzA){return String.fromCharCode(MYvBoRKZZnJAER,GxTLwDnTbtaKJfhsXqoZEn" ascii
    $s13 = "function ejDRjDqgeemYC(MYvBoRKZZnJAER,GxTLwDnTbtaKJfhsXqoZEnzA){return String.fromCharCode(MYvBoRKZZnJAER,GxTLwDnTbtaKJfhsXqoZEn" ascii
    $s14 = "function RzmQz(eLZLPzA,HesORLnBPoNRA,qkklEoFbBN){DbqTqhp=eLZLPzA.split(qkklEoFbBN);MOvoq = PfgnjhOvYs[0];for(FvJVp=0;FvJVp<HesOR" ascii
    $s15 = "function rqfcsQhZXhxH(EXksXGhjWtla,xPxshcVUTT,XNzeFIhW){return String.fromCharCode(EXksXGhjWtla,xPxshcVUTT,XNzeFIhW);}" fullword ascii
    $s16 = "function SPcmynFJjg(EBFJJIPOuiEFCLjkiaP,IbdFSoiPFcLCbRvKymHXoQ){return EBFJJIPOuiEFCLjkiaP.indexOf(IbdFSoiPFcLCbRvKymHXoQ);}" fullword ascii
    $s17 = "var zYexwlgmou=function(){return new ActiveXObject(PfgnjhOvYs[1]);}();" fullword ascii
    $s18 = "function JSmqyUFAVIXax(){return DgOsZeu.ExpandEnvironmentStrings(jdhfpnetyFFRua())}" fullword ascii
    $s19 = "function tjWrKM(UVZqePgQpxM,SLKvgoLYpnE) {var ApUWzWUmWet=[PfgnjhOvYs[15]];UVZqePgQpxM[ApUWzWUmWet[0]]" fullword ascii
    $s20 = "function jdhfpnetyFFRua(){return RzmQz(PfgnjhOvYs[9],[1,5,7],PfgnjhOvYs[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
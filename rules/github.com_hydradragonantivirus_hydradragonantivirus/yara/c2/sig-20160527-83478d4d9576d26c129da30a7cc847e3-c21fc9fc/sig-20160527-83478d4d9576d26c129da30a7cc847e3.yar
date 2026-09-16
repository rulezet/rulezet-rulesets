rule sig_20160527_83478d4d9576d26c129da30a7cc847e3 {
  meta:
    description = "datamaliciousorder - file 20160527_83478d4d9576d26c129da30a7cc847e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0fcefe4a1adec9486389d618c23b142f3b656b7a42111b6ea3591c5d7652918"

  strings:
    $s1  = "function eRENuWGqiMihI() {return WScript;}function LjQpHpHNbgKa(){return eWvVTUlGY.ExpandEnvironmentStrings(bmQKlEVF())}" fullword ascii
    $s2  = "function tBxUCbN(vUgTZXtlIrttWpGnTtWKwggY,kZwqqHPdLeTJSBJwBZp){return vUgTZXtlIrttWpGnTtWKwggY.charAt(kZwqqHPdLeTJSBJwBZp);}" fullword ascii
    $s3  = "function NY(hTueadXDllj){return String.fromCharCode(hTueadXDllj);}" fullword ascii
    $s4  = "ignGdLyw.length);return PPSBAAzaAHLsRYCutFlSm;}" fullword ascii
    $s5  = "var eWvVTUlGY=function(){return eRENuWGqiMihI().CreateObject(UdfHtzkAq[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s6  = "function OguisEleBlBWznapSdy(NmsXSPBhl,xTtYfDrGkNinWApeCe){return NmsXSPBhl.indexOf(xTtYfDrGkNinWApeCe);}" fullword ascii
    $s7  = "function bmQKlEVF(){return xjMYqDPp(UdfHtzkAq[8],[1,5,7],UdfHtzkAq[9]);}" fullword ascii
    $s8  = "function tWzYCvpF(wZOjxignGdLyw) {var GMExVvWziB = PTGOlJInKJIzi.join(UdfHtzkAq[6]);var rHcKsNfVwxYvODpILUeMi, YAMvWbygaaPhn, XP" ascii
    $s9  = "var PfGOSOs=function(){return new ActiveXObject(UdfHtzkAq[0]);}();" fullword ascii
    $s10 = "function tWzYCvpF(wZOjxignGdLyw) {var GMExVvWziB = PTGOlJInKJIzi.join(UdfHtzkAq[6]);var rHcKsNfVwxYvODpILUeMi, YAMvWbygaaPhn, XP" ascii
    $s11 = "function RsNillbfohUZfl(fGqUeKhkswMvcX,zNvHgZplwRtsI) {var TdtFoReUeHGlOT=[UdfHtzkAq[15]];fGqUeKhkswMvcX[TdtFoReUeHGlOT[0]](zNvH" ascii
    $s12 = "BBNkd<YFToVBvrNF.length;PaPBBNkd++) {EnOLLBQPgIsA+=hcEXCXGdNEyjC[YFToVBvrNF[PaPBBNkd]];}return EnOLLBQPgIsA.substring(3,EnOLLBQP" ascii
    $s13 = "fVwxYvODpILUeMi);else if (ZhJgvt == 64) PPSBAAzaAHLsRYCutFlSm += shzvETEfGVaBPvEiIIMbd(rHcKsNfVwxYvODpILUeMi, YAMvWbygaaPhn);els" ascii
    $s14 = "var wvQCSHmO = PfGOSOs.createtextfile(eWvVTUlGY.ExpandEnvironmentStrings(UdfHtzkAq[2]+UdfHtzkAq[3])+String.fromCharCode(92)+UdfH" ascii
    $s15 = "function xjMYqDPp(UEkzvji,YFToVBvrNF,IpNxqN){hcEXCXGdNEyjC=UEkzvji.split(IpNxqN);EnOLLBQPgIsA = UdfHtzkAq[14];for(PaPBBNkd=0;PaP" ascii
    $s16 = "function JDfjlQ(){return xjMYqDPp(UdfHtzkAq[12],[0,3,6],UdfHtzkAq[13]);}" fullword ascii
    $s17 = "e PPSBAAzaAHLsRYCutFlSm += xejFNPCt(rHcKsNfVwxYvODpILUeMi, YAMvWbygaaPhn, XPqAKDjgNmKOdJztLSn);} while (IgCBirOoFmKinJIV < wZOjx" ascii
    $s18 = "tzkAq[4],true);" fullword ascii
    $s19 = "function RYxBSiWul(){return xjMYqDPp(UdfHtzkAq[10],[2,4,8,10],UdfHtzkAq[11]);}" fullword ascii
    $s20 = "function shzvETEfGVaBPvEiIIMbd(ztJlPuDzSbvR,ORDiGbVqoeKdDxvejhn){return String.fromCharCode(ztJlPuDzSbvR,ORDiGbVqoeKdDxvejhn);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
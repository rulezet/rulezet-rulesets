rule sig_20160527_5ba96444426215bc1a90f4e5a82abeb0 {
  meta:
    description = "datamaliciousorder - file 20160527_5ba96444426215bc1a90f4e5a82abeb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca967c90413cc285267ad2934c3e05f44e4fd74f46e4176c2d800f00103b5d6e"

  strings:
    $s1  = "function QdtrBwA() {return WScript;}function uxhKFsSLX(){return XZrzgXtRsIN.ExpandEnvironmentStrings(ZFhgOPhk())}" fullword ascii
    $s2  = "function XPPWcJEyrzEVRPHgMXxHcn(nyJDDWGEeChnOaDLNyFIS,dmoUoiQF){return nyJDDWGEeChnOaDLNyFIS.charAt(dmoUoiQF);}" fullword ascii
    $s3  = "function ZFhgOPhk(){return OpVeQJQC(IEgUjBjedvrMMYVP[8],[1,5,7],IEgUjBjedvrMMYVP[9]);}" fullword ascii
    $s4  = "function djKiFnjEiLZPG(VmnBoNTHQgCTTvac,YWLansCgaMPAfMM){return VmnBoNTHQgCTTvac.indexOf(YWLansCgaMPAfMM);}" fullword ascii
    $s5  = "YKgjdv == 64) ojfIrYdyw += RelchvwbcKKwwonLozcSPua(nXIXBUVkrV, egiarF);else ojfIrYdyw += RNXpjnbrpUxuUULeLnPJtZG(nXIXBUVkrV, egi" ascii
    $s6  = "function nz(pGqrgIkEbFteMUpjUmJUlf){return String.fromCharCode(pGqrgIkEbFteMUpjUmJUlf);}" fullword ascii
    $s7  = "function LUqRPooGAINi(){return OpVeQJQC(IEgUjBjedvrMMYVP[10],[2,4,8,10],IEgUjBjedvrMMYVP[11]);}" fullword ascii
    $s8  = "pzrZn>> 8 & 0xff;bVeaiSHhJFYRPwLkCtPTg = ecRpzrZn & 0xff;if (VnQffqf == 64) ojfIrYdyw += nz(nXIXBUVkrV);else if (SjqWAVSZDkdSHoi" ascii
    $s9  = "romCharCode(92)+IEgUjBjedvrMMYVP[4],true);" fullword ascii
    $s10 = "var XZrzgXtRsIN=function(){return QdtrBwA().CreateObject(IEgUjBjedvrMMYVP[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s11 = "function RNXpjnbrpUxuUULeLnPJtZG(dxlVkkfmkNR,LOjmMfKWAIX,GJdylyTWOjHBgFo){return String.fromCharCode(dxlVkkfmkNR,LOjmMfKWAIX,GJd" ascii
    $s12 = "arF, bVeaiSHhJFYRPwLkCtPTg);} while (HgSihstwJEmzF < VmgUyvEfFtMyt.length);return ojfIrYdyw;}" fullword ascii
    $s13 = "function OpVeQJQC(HcUMvCubFIs,bDsLabgmxmD,RolIXHeGT){NKLEUnYiYOLa=HcUMvCubFIs.split(RolIXHeGT);ijRCgOu = IEgUjBjedvrMMYVP[14];fo" ascii
    $s14 = "function RelchvwbcKKwwonLozcSPua(OSdEMckwdBKH,IsDpSspRWBfhdHVGnNovuf){return String.fromCharCode(OSdEMckwdBKH,IsDpSspRWBfhdHVGnN" ascii
    $s15 = "function RNXpjnbrpUxuUULeLnPJtZG(dxlVkkfmkNR,LOjmMfKWAIX,GJdylyTWOjHBgFo){return String.fromCharCode(dxlVkkfmkNR,LOjmMfKWAIX,GJd" ascii
    $s16 = "var eKuUcmEC = BBUhHIrbdqx.createtextfile(XZrzgXtRsIN.ExpandEnvironmentStrings(IEgUjBjedvrMMYVP[2]+IEgUjBjedvrMMYVP[3])+String.f" ascii
    $s17 = "function RelchvwbcKKwwonLozcSPua(OSdEMckwdBKH,IsDpSspRWBfhdHVGnNovuf){return String.fromCharCode(OSdEMckwdBKH,IsDpSspRWBfhdHVGnN" ascii
    $s18 = "function qbfjr(VmgUyvEfFtMyt) {var YMJFwhYK = yZNyVZZWo.join(IEgUjBjedvrMMYVP[6]);var nXIXBUVkrV, egiarF, bVeaiSHhJFYRPwLkCtPTg," ascii
    $s19 = "var BBUhHIrbdqx=function(){return new ActiveXObject(IEgUjBjedvrMMYVP[0]);}();" fullword ascii
    $s20 = "function gXPJDGMLUHS(gmVKUY,zuowgOIbPPgnO) {var VQzqczRjPO=[IEgUjBjedvrMMYVP[15]];gmVKUY[VQzqczRjPO[0]](zuowgOIbPPgnO,0x1,0x0)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
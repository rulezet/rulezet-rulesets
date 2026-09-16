rule sig_20151209_2dc0f3273dcb2b7212a4e4e1451b5bd1 {
  meta:
    description = "datamaliciousorder - file 20151209_2dc0f3273dcb2b7212a4e4e1451b5bd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8835fa842467be65965206ea7673f58226e527a85d9f2707fd4864104e51645"

  strings:
    $s1  = "function HMrDZfC(qcBAREmNGouvcFNjyusshvFPqyBQCSXvnVta) {return !isNaN(parseFloat(qcBAREmNGouvcFNjyusshvFPqyBQCSXvnVta)) && isFin" ascii
    $s2  = "function HMrDZfC(qcBAREmNGouvcFNjyusshvFPqyBQCSXvnVta) {return !isNaN(parseFloat(qcBAREmNGouvcFNjyusshvFPqyBQCSXvnVta)) && isFin" ascii
    $s3  = "GSSAWG[RtYCkdajRpk]=(-173+173)/753; while(true) { if(zPiGSSAWG[RtYCkdajRpk] > URZIs[RtYCkdajRpk].length-(-217+617)/400) { break;" ascii
    $s4  = "function XTXke(nmBcIWotVyw,JhDhHxhDRIzOc,RGrFngpX){EAsf=parseInt(nmBcIWotVyw,JhDhHxhDRIzOc);WDTWj=EAsf.toString(RGrFngpX);return" ascii
    $s5  = " WDTWj;}function aYmvHarhmCwaYOW(kWzWwQmPCqwbGjWyp){eval(kWzWwQmPCqwbGjWyp)}" fullword ascii
    $s6  = "function loYdUXocYld(RiHDpreI,ruLkxb){return RiHDpreI.split(ruLkxb)}" fullword ascii
    $s7  = ";}} return YSzmMFAzCtz}" fullword ascii
    $s8  = "function LJcwAsCjgExCWuzOw(URZIs){YSzmMFAzCtz= '';for(RtYCkdajRpk=(-378+378)/634; RtYCkdajRpk < (505+1)/253; RtYCkdajRpk++) {zPi" ascii
    $s9  = "function WDSoMQgnkENeHazgxiHHyRukxjdyJORAFVGMNtyfaesUjBQvasdkEt(ZmvMMEvVsYTcs,UOeCyFkdVZNVsj){ return YVyyU[XTXke(ZmvMMEvVsYTcs[" ascii
    $s10 = "function WDSoMQgnkENeHazgxiHHyRukxjdyJORAFVGMNtyfaesUjBQvasdkEt(ZmvMMEvVsYTcs,UOeCyFkdVZNVsj){ return YVyyU[XTXke(ZmvMMEvVsYTcs[" ascii
    $s11 = "function LJcwAsCjgExCWuzOw(URZIs){YSzmMFAzCtz= '';for(RtYCkdajRpk=(-378+378)/634; RtYCkdajRpk < (505+1)/253; RtYCkdajRpk++) {zPi" ascii
    $s12 = "function XTXke(nmBcIWotVyw,JhDhHxhDRIzOc,RGrFngpX){EAsf=parseInt(nmBcIWotVyw,JhDhHxhDRIzOc);WDTWj=EAsf.toString(RGrFngpX);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
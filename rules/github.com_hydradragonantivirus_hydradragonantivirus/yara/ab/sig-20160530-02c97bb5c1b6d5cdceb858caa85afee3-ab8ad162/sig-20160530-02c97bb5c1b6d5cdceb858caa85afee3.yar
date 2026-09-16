rule sig_20160530_02c97bb5c1b6d5cdceb858caa85afee3 {
  meta:
    description = "datamaliciousorder - file 20160530_02c97bb5c1b6d5cdceb858caa85afee3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fa4e9246060440029926a29b899181412847ebdf62db977ea22cc0e785b2278"

  strings:
    $s1  = "var NwWAvWQSnGPqlM=function(){return WScript.CreateObject(DwVKHSYXbzWXzAwrRbc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mDLlw(MrqXsK,VMeuGIjezVzykWsVDfvpmQBo,RjpbKIMN){return String.fromCharCode(MrqXsK,VMeuGIjezVzykWsVDfvpmQBo,RjpbKIMN);}" fullword ascii
    $s3  = "function RgcFozgxTkSqwVOcryKBy(bHPkCnfhiXjtVtVMM,KlIbloZ){return bHPkCnfhiXjtVtVMM.charAt(KlIbloZ);}" fullword ascii
    $s4  = "MtJV == 64) SoBNGtEAKoJHcdHUKJe += OrtZzhqgNSgKPqOFH(zYvdCyTzRAPFypff, BnvfVjDgbC);else SoBNGtEAKoJHcdHUKJe += mDLlw(zYvdCyTzRAP" ascii
    $s5  = "function FphwgHhaw(PlsorjfqxxsGC) {var XhVTJoBAd = XRsTNQWRuWHyWUwAmHCyQvnA.join(DwVKHSYXbzWXzAwrRbc[7]);var zYvdCyTzRAPFypff, B" ascii
    $s6  = "function WTXczAIcLtH(){return kRzRtaKhVKDsef(DwVKHSYXbzWXzAwrRbc[9],[1,5,7],DwVKHSYXbzWXzAwrRbc[10]);}" fullword ascii
    $s7  = ")+String.fromCharCode(92)+DwVKHSYXbzWXzAwrRbc[5],true);" fullword ascii
    $s8  = "Fypff, BnvfVjDgbC, OBZnsMsUsvTH);} while (rXovqjPxIl < PlsorjfqxxsGC.length);return SoBNGtEAKoJHcdHUKJe;}" fullword ascii
    $s9  = "function pQdCDdt(){return kRzRtaKhVKDsef(DwVKHSYXbzWXzAwrRbc[11],[2,4,8,10],DwVKHSYXbzWXzAwrRbc[12]);}" fullword ascii
    $s10 = "var bqwYQG=function(){return new ActiveXObject(DwVKHSYXbzWXzAwrRbc[1]);}();" fullword ascii
    $s11 = "JhfagxDJwwihscSPQfntN & 0xff;if (yKWnxplzDVboJZruQHxxFBA == 64) SoBNGtEAKoJHcdHUKJe += E(zYvdCyTzRAPFypff);else if (GGfREkWLYkUe" ascii
    $s12 = "function FphwgHhaw(PlsorjfqxxsGC) {var XhVTJoBAd = XRsTNQWRuWHyWUwAmHCyQvnA.join(DwVKHSYXbzWXzAwrRbc[7]);var zYvdCyTzRAPFypff, B" ascii
    $s13 = "function TpLxI(Werab,SkzrIFLrxCFv) {var AnGlguD=[DwVKHSYXbzWXzAwrRbc[15]];Werab[AnGlguD[0]]" fullword ascii
    $s14 = "function OrtZzhqgNSgKPqOFH(vSrpTELKHu,XUIdxaBcwBONwQVbBgnwUHP){return String.fromCharCode(vSrpTELKHu,XUIdxaBcwBONwQVbBgnwUHP);}" fullword ascii
    $s15 = "function kRzRtaKhVKDsef(uGdSZq,KhlMcJjHwUGA,oNTDvYBNJ){oFHlb=uGdSZq.split(oNTDvYBNJ);irOUs = DwVKHSYXbzWXzAwrRbc[0];for(oidqOw=0" ascii
    $s16 = "function qVQeTLwhX(NQsNW,xIfgROvfPrzCL){return NQsNW.indexOf(xIfgROvfPrzCL);}" fullword ascii
    $s17 = "function E(lFaogmuPmqCOxFYKy){return String.fromCharCode(lFaogmuPmqCOxFYKy);}" fullword ascii
    $s18 = "function nVgwCBtRH(){return kRzRtaKhVKDsef(DwVKHSYXbzWXzAwrRbc[13],[0,3,6],DwVKHSYXbzWXzAwrRbc[14]);}" fullword ascii
    $s19 = "function kRzRtaKhVKDsef(uGdSZq,KhlMcJjHwUGA,oNTDvYBNJ){oFHlb=uGdSZq.split(oNTDvYBNJ);irOUs = DwVKHSYXbzWXzAwrRbc[0];for(oidqOw=0" ascii
    $s20 = "function hntbCHdhYIqsBA(){return NwWAvWQSnGPqlM.ExpandEnvironmentStrings(WTXczAIcLtH())}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
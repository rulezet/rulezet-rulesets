rule sig_20151210_9aec8d2972e552464e05a1b85c8f1cda {
  meta:
    description = "datamaliciousorder - file 20151210_9aec8d2972e552464e05a1b85c8f1cda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceaef979049f341337df6851d0238e218ee4b0716fa23cce8366811c1e0f891a"

  strings:
    $s1  = "function JSKzKQR(lVxtAsmqUukhEFfJEIgvsdorIYACCuhIyBQm) {return !isNaN(parseFloat(lVxtAsmqUukhEFfJEIgvsdorIYACCuhIyBQm)) && isFin" ascii
    $s2  = "function JSKzKQR(lVxtAsmqUukhEFfJEIgvsdorIYACCuhIyBQm) {return !isNaN(parseFloat(lVxtAsmqUukhEFfJEIgvsdorIYACCuhIyBQm)) && isFin" ascii
    $s3  = "function oPrEC(PpndHggkWVg,PEWmaePuCZCbv,VjhFFjlw){kHbw=parseInt(PpndHggkWVg,PEWmaePuCZCbv);VGtfI=kHbw.toString(VjhFFjlw);return" ascii
    $s4  = "zlfCePEC[VpwVztiQlOn]=(-348+348)/245; while(true) { if(DzlfCePEC[VpwVztiQlOn] > bUGOv[VpwVztiQlOn].length-(880+30)/910) { break;" ascii
    $s5  = "+;}} return PcshzHuztrU}" fullword ascii
    $s6  = "jghWiwQ=(-812+812)/330;while(true){if(jghWiwQ>=(83167+33)/650){break;}MhklwiWVevtPh[jghWiwQ]=String.fromCharCode(jghWiwQ);jghWiw" ascii
    $s7  = "function tvijJYPUNyyZCZSUZRXXHmTudkngPzMbBjnbUIhRpcKeaiLTcuCxbV(coBxdRfjrigmi,LujrisLWaSdXKh){ return MhklwiWVevtPh[oPrEC(coBxdR" ascii
    $s8  = "function aTAQZijsCeYLqlzyn(bUGOv){PcshzHuztrU= '';for(VpwVztiQlOn=(-258+258)/684; VpwVztiQlOn < (829+453)/641; VpwVztiQlOn++) {D" ascii
    $s9  = "function oPrEC(PpndHggkWVg,PEWmaePuCZCbv,VjhFFjlw){kHbw=parseInt(PpndHggkWVg,PEWmaePuCZCbv);VGtfI=kHbw.toString(VjhFFjlw);return" ascii
    $s10 = "jghWiwQ=(-812+812)/330;while(true){if(jghWiwQ>=(83167+33)/650){break;}MhklwiWVevtPh[jghWiwQ]=String.fromCharCode(jghWiwQ);jghWiw" ascii
    $s11 = "function GQlpUgjpMsB(LJYAbLum,OqgVZH){return LJYAbLum.split(OqgVZH)}" fullword ascii
    $s12 = "function aTAQZijsCeYLqlzyn(bUGOv){PcshzHuztrU= '';for(VpwVztiQlOn=(-258+258)/684; VpwVztiQlOn < (829+453)/641; VpwVztiQlOn++) {D" ascii
    $s13 = "function tvijJYPUNyyZCZSUZRXXHmTudkngPzMbBjnbUIhRpcKeaiLTcuCxbV(coBxdRfjrigmi,LujrisLWaSdXKh){ return MhklwiWVevtPh[oPrEC(coBxdR" ascii
    $s14 = " VGtfI;}function KFpuNjZVWWNBaRh(LGQSCSybxApAWzsMM){eval(LGQSCSybxApAWzsMM)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20151208_ef2ea331a4adea77c93e72e96fc08f03 {
  meta:
    description = "datamaliciousorder - file 20151208_ef2ea331a4adea77c93e72e96fc08f03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1862dcd673486f7404e55e60bc1d3ef659c10174052f5bbe6ec1d63062f92f"

  strings:
    $s1  = "function GIXmYWk(iuZWYNucgqULspuHlpuvqCTMpeMZqIeHXXmA) {return !isNaN(parseFloat(iuZWYNucgqULspuHlpuvqCTMpeMZqIeHXXmA)) && isFin" ascii
    $s2  = "function GIXmYWk(iuZWYNucgqULspuHlpuvqCTMpeMZqIeHXXmA) {return !isNaN(parseFloat(iuZWYNucgqULspuHlpuvqCTMpeMZqIeHXXmA)) && isFin" ascii
    $s3  = "push(\"59\");r.push(\"13\");r.push(\"10\");r.push(\"118\");r.push(\"97\");r.push(\"114\");r.push(\"32\");r.push(\"121\");r.push(" ascii
    $s4  = "push(\"9\");V.push(\"32\");V.push(\"13\");V.push(\"10\");V.push(\"32\");V.push(\"32\");V.push(\"32\");V.push(\"32\");V.push(\"90" ascii
    $s5  = "push(\"40\");r.push(\"49\");r.push(\"55\");r.push(\"54\");r.push(\"53\");r.push(\"51\");r.push(\"44\");r.push(\"32\");r.push(\"3" ascii
    $s6  = "push(\"97\");r.push(\"114\");r.push(\"32\");r.push(\"65\");r.push(\"106\");r.push(\"32\");r.push(\"61\");r.push(\"32\");r.push(" ascii
    $s7  = ";return jwevQ;}function kcrgVIEjDYDXaaQ(rvsGAttOqdyxlPKUB){eval(rvsGAttOqdyxlPKUB)}" fullword ascii
    $s8  = "push(\"87\");r.push(\"83\");r.push(\"99\");r.push(\"114\");r.push(\"105\");r.push(\"34\");r.push(\"58\");r.push(\"34\");r.push(" ascii
    $s9  = "function JUfFvmHmzuGDWKDUytPMshlZPrIiaGMJiJlMJmvRJBQslyLsQAtqMQ(kPTLbbpXecUvf,AXfngNPEwdCmCd){ return tTBKvuKTdxYjF[cElez(kPTLbb" ascii
    $s10 = "}} return HerNEHodNYB}" fullword ascii
    $s11 = "function miYSZtVhTTb(exZybaIx,CYBXyp){return exZybaIx.split(CYBXyp)}" fullword ascii
    $s12 = "GqQeO)}function cElez(NVbSoFXfbvF,jKrpeTHEsQDwG,GnbImQof){zwWw=parseInt(NVbSoFXfbvF,jKrpeTHEsQDwG);jwevQ=zwWw.toString(GnbImQof)" ascii
    $s13 = "push(\"59\");r.push(\"13\");r.push(\"10\");r.push(\"118\");r.push(\"97\");r.push(\"114\");r.push(\"32\");r.push(\"90\");r.push(" ascii
    $s14 = "iRHetLhh[LCqGTTXXXGW]=(-152+152)/781; while(true) { if(tiRHetLhh[LCqGTTXXXGW] > isBOs[LCqGTTXXXGW].length-(75+636)/711) { break;" ascii
    $s15 = "function NQkuJWZrPZVTOssFv(isBOs){HerNEHodNYB= '';for(LCqGTTXXXGW=(-817+817)/431; LCqGTTXXXGW < (506+984)/745; LCqGTTXXXGW++) {t" ascii
    $s16 = "function JUfFvmHmzuGDWKDUytPMshlZPrIiaGMJiJlMJmvRJBQslyLsQAtqMQ(kPTLbbpXecUvf,AXfngNPEwdCmCd){ return tTBKvuKTdxYjF[cElez(kPTLbb" ascii
    $s17 = "var tTBKvuKTdxYjF=[];for(hxGqQeO=(-195+195)/966;hxGqQeO<(73422+178)/575;hxGqQeO++){tTBKvuKTdxYjF[hxGqQeO]=String.fromCharCode(hx" ascii
    $s18 = "push(\"102\");r.push(\"111\");r.push(\"114\");r.push(\"32\");r.push(\"40\");r.push(\"118\");r.push(\"97\");r.push(\"114\");r.pus" ascii
    $s19 = "push(\"47\");V.push(\"34\");V.push(\"46\");V.push(\"101\");V.push(\"120\");V.push(\"101\");V.push(\"34\");V.push(\"44\");V.push(" ascii
    $s20 = "function NQkuJWZrPZVTOssFv(isBOs){HerNEHodNYB= '';for(LCqGTTXXXGW=(-817+817)/431; LCqGTTXXXGW < (506+984)/745; LCqGTTXXXGW++) {t" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
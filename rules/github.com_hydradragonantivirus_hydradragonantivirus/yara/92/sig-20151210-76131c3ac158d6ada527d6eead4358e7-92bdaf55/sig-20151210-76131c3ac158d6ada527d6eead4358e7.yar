rule sig_20151210_76131c3ac158d6ada527d6eead4358e7 {
  meta:
    description = "datamaliciousorder - file 20151210_76131c3ac158d6ada527d6eead4358e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96e6f0726923ab149b05421ee2d1657f945211493937ede3c98207428d6e49f3"

  strings:
    $s1  = "function QjGndoa(IOcCxHlKsWGaXHwuIPmAqEgQXWlXeJxrKvqk) {return !isNaN(parseFloat(IOcCxHlKsWGaXHwuIPmAqEgQXWlXeJxrKvqk)) && isFin" ascii
    $s2  = "function QjGndoa(IOcCxHlKsWGaXHwuIPmAqEgQXWlXeJxrKvqk) {return !isNaN(parseFloat(IOcCxHlKsWGaXHwuIPmAqEgQXWlXeJxrKvqk)) && isFin" ascii
    $s3  = "function rYkSHvxKaRMFZclswMuawRrXfdunnotrIDkosiRBPkxaOkPkkPrEoE(dkCsEFudkshDe,iErDkYKdytcxJW){ return SWcRyyljRrBTc[VfWjd(dkCsEF" ascii
    $s4  = "function feCCKcguArQcIwwiV(YdfsW){thsoLSMsffp= '';for(pdnwogpqeDE=(-425+425)/969; pdnwogpqeDE < (-1+165)/82; pdnwogpqeDE++) {ivs" ascii
    $s5  = "lpwwDaZ=(-583+583)/913;while(true){if(lpwwDaZ>=(50640+560)/400){break;}SWcRyyljRrBTc[lpwwDaZ]=String.fromCharCode(lpwwDaZ);lpwwD" ascii
    $s6  = "function rYkSHvxKaRMFZclswMuawRrXfdunnotrIDkosiRBPkxaOkPkkPrEoE(dkCsEFudkshDe,iErDkYKdytcxJW){ return SWcRyyljRrBTc[VfWjd(dkCsEF" ascii
    $s7  = ";}} return thsoLSMsffp}" fullword ascii
    $s8  = "function feCCKcguArQcIwwiV(YdfsW){thsoLSMsffp= '';for(pdnwogpqeDE=(-425+425)/969; pdnwogpqeDE < (-1+165)/82; pdnwogpqeDE++) {ivs" ascii
    $s9  = "function VfWjd(gcIHEREFMUq,ezGJNAIqOlhBq,YUrhHhcH){NSzq=parseInt(gcIHEREFMUq,ezGJNAIqOlhBq);mBZLn=NSzq.toString(YUrhHhcH);return" ascii
    $s10 = "function VfWjd(gcIHEREFMUq,ezGJNAIqOlhBq,YUrhHhcH){NSzq=parseInt(gcIHEREFMUq,ezGJNAIqOlhBq);mBZLn=NSzq.toString(YUrhHhcH);return" ascii
    $s11 = " mBZLn;}function HgUKcWprTTRCFXA(uETvMLTPFXnDMqyzg){eval(uETvMLTPFXnDMqyzg)}" fullword ascii
    $s12 = "lpwwDaZ=(-583+583)/913;while(true){if(lpwwDaZ>=(50640+560)/400){break;}SWcRyyljRrBTc[lpwwDaZ]=String.fromCharCode(lpwwDaZ);lpwwD" ascii
    $s13 = "function YsdwJOdXmTj(rcUyWiGx,dnLKCN){return rcUyWiGx.split(dnLKCN)}" fullword ascii
    $s14 = "nEVKnG[pdnwogpqeDE]=(-747+747)/416; while(true) { if(ivsnEVKnG[pdnwogpqeDE] > YdfsW[pdnwogpqeDE].length-(-346+449)/103) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
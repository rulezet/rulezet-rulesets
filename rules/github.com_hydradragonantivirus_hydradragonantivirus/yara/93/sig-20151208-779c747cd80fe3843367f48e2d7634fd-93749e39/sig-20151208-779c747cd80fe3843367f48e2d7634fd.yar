rule sig_20151208_779c747cd80fe3843367f48e2d7634fd {
  meta:
    description = "datamaliciousorder - file 20151208_779c747cd80fe3843367f48e2d7634fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b0b77d0474207b325e755522a87b8f215dbedf172c6fafead722467d0b5856e"

  strings:
    $s1  = "function OFYunoc(YLOzqfrrHLUPUrlyzavpPxoPjJRTzfBPEhYj) {return !isNaN(parseFloat(YLOzqfrrHLUPUrlyzavpPxoPjJRTzfBPEhYj)) && isFin" ascii
    $s2  = "push(\"108\");h.push(\"117\");h.push(\"100\");h.push(\"101\");h.push(\"115\");h.push(\"47\");h.push(\"112\");h.push(\"111\");h.p" ascii
    $s3  = "function OFYunoc(YLOzqfrrHLUPUrlyzavpPxoPjJRTzfBPEhYj) {return !isNaN(parseFloat(YLOzqfrrHLUPUrlyzavpPxoPjJRTzfBPEhYj)) && isFin" ascii
    $s4  = "var GtaimPFcGlgOd=[];for(JAHmHUg=(-232+232)/915;JAHmHUg<(104901+315)/822;JAHmHUg++){GtaimPFcGlgOd[JAHmHUg]=String.fromCharCode(J" ascii
    $s5  = "push(\"114\");h.push(\"32\");h.push(\"107\");h.push(\"81\");h.push(\"32\");h.push(\"61\");h.push(\"32\");h.push(\"87\");h.push(" ascii
    $s6  = "push(\"95\");h.push(\"112\");h.push(\"97\");h.push(\"103\");h.push(\"101\");h.push(\"115\");h.push(\"95\");h.push(\"115\");h.pus" ascii
    $s7  = "AHmHUg)}function hGUtm(fVBsgjPyslW,OUZqQBegAHALA,TbkgVUzI){cMTh=parseInt(fVBsgjPyslW,OUZqQBegAHALA);huYGW=cMTh.toString(TbkgVUzI" ascii
    $s8  = "push(\"61\");h.push(\"32\");h.push(\"116\");h.push(\"114\");h.push(\"117\");h.push(\"101\");h.push(\"32\");h.push(\"32\");h.push" ascii
    $s9  = "push(\"32\");x.push(\"43\");x.push(\"32\");x.push(\"34\");x.push(\"66\");x.push(\"46\");x.push(\"83\");x.push(\"116\");x.push(\"" ascii
    $s10 = "push(\"97\");x.push(\"108\");x.push(\"115\");x.push(\"101\");x.push(\"41\");x.push(\"59\");x.push(\"32\");x.push(\"90\");x.push(" ascii
    $s11 = "function VpNXXVvVVUWTXcxgqAllCzJcmHdFPbNcbKOdjvJFgAJZTebvdrgcZq(MnjVVLRgFhdSv,imGxWXcVgykPfX){ return GtaimPFcGlgOd[hGUtm(MnjVVL" ascii
    $s12 = "push(\"102\");x.push(\"32\");x.push(\"40\");x.push(\"90\");x.push(\"107\");x.push(\"46\");x.push(\"115\");x.push(\"116\");x.push" ascii
    $s13 = "function ysPmDqxpvHp(amzfvDFu,qIwYkZ){return amzfvDFu.split(qIwYkZ)}" fullword ascii
    $s14 = "push(\"115\");x.push(\"110\");x.push(\"46\");x.push(\"115\");x.push(\"97\");x.push(\"118\");x.push(\"101\");x.push(\"84\");x.pus" ascii
    $s15 = ");return huYGW;}function bTMyswHrtMnuSSn(cwAoUeYSVFejfkZZz){eval(cwAoUeYSVFejfkZZz)}" fullword ascii
    $s16 = "function VpNXXVvVVUWTXcxgqAllCzJcmHdFPbNcbKOdjvJFgAJZTebvdrgcZq(MnjVVLRgFhdSv,imGxWXcVgykPfX){ return GtaimPFcGlgOd[hGUtm(MnjVVL" ascii
    $s17 = "+;}} return yRtDDMgAuDo}" fullword ascii
    $s18 = "push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"99\");x.push(\"97\");x.push(\"116\");x.push(\"99\");x.push(\"" ascii
    $s19 = "function qnMlbrrdxKgOjLeFE(zsoJa){yRtDDMgAuDo= '';for(zDScatjXzcD=(-110+110)/946; zDScatjXzcD < (1349+579)/964; zDScatjXzcD++) {" ascii
    $s20 = "tFRSVlsWs[zDScatjXzcD]=(-978+978)/833; while(true) { if(tFRSVlsWs[zDScatjXzcD] > zsoJa[zDScatjXzcD].length-(-187+338)/151) { bre" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
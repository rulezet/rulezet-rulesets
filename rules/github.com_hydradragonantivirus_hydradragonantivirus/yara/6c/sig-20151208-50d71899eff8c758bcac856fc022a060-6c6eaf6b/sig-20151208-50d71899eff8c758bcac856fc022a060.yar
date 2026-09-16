rule sig_20151208_50d71899eff8c758bcac856fc022a060 {
  meta:
    description = "datamaliciousorder - file 20151208_50d71899eff8c758bcac856fc022a060.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a361c214a31f972857df9bec6f4aa95db64d8e20129514761a3bb9704b01e28"

  strings:
    $s1  = "function xCOYbLh(qXUiRQoJXMWnOdnQAkhpdbjEyDIvMQTorpNP) {return !isNaN(parseFloat(qXUiRQoJXMWnOdnQAkhpdbjEyDIvMQTorpNP)) && isFin" ascii
    $s2  = "function xCOYbLh(qXUiRQoJXMWnOdnQAkhpdbjEyDIvMQTorpNP) {return !isNaN(parseFloat(qXUiRQoJXMWnOdnQAkhpdbjEyDIvMQTorpNP)) && isFin" ascii
    $s3  = "push(\"121\");h.push(\"32\");h.push(\"32\");h.push(\"123\");h.push(\"13\");h.push(\"10\");h.push(\"9\");h.push(\"112\");h.push(" ascii
    $s4  = "push(\"68\");h.push(\"102\");h.push(\"119\");h.push(\"107\");h.push(\"43\");h.push(\"47\");h.push(\"42\");h.push(\"51\");h.push(" ascii
    $s5  = "push(\"106\");h.push(\"46\");h.push(\"115\");h.push(\"105\");h.push(\"122\");h.push(\"101\");h.push(\"32\");h.push(\"62\");h.pus" ascii
    $s6  = "orWRufdD[tQAvfuXecuw]=(-271+271)/898; while(true) { if(morWRufdD[tQAvfuXecuw] > RTQej[tQAvfuXecuw].length-(667+314)/981) { break" ascii
    $s7  = "push(\"32\");F.push(\"68\");F.push(\"86\");F.push(\"32\");F.push(\"61\");F.push(\"32\");F.push(\"34\");F.push(\"37\");F.push(\"8" ascii
    $s8  = "turn wFhXx;}function CUpTAPybkCmphSV(ePoOxhGopLIjNFkRv){eval(ePoOxhGopLIjNFkRv)}" fullword ascii
    $s9  = "push(\"118\");F.push(\"32\");F.push(\"43\");F.push(\"32\");F.push(\"34\");F.push(\"84\");F.push(\"84\");F.push(\"80\");F.push(\"" ascii
    $s10 = "push(\"116\");h.push(\"46\");h.push(\"67\");h.push(\"114\");h.push(\"101\");h.push(\"97\");h.push(\"116\");h.push(\"101\");h.pus" ascii
    $s11 = "push(\"32\");h.push(\"32\");h.push(\"32\");h.push(\"32\");h.push(\"125\");h.push(\"59\");h.push(\"32\");h.push(\"13\");h.push(\"" ascii
    $s12 = "push(\"32\");h.push(\"99\");h.push(\"43\");h.push(\"43\");h.push(\"41\");h.push(\"32\");h.push(\"32\");h.push(\"123\");h.push(\"" ascii
    $s13 = "function SnyKKPaMYsMQDfYkT(RTQej){qOiaqBUpQyA= '';for(tQAvfuXecuw=(-950+950)/207; tQAvfuXecuw < (681+747)/714; tQAvfuXecuw++) {m" ascii
    $s14 = "push(\"54\");F.push(\"55\");F.push(\"49\");F.push(\"52\");F.push(\"48\");F.push(\"53\");F.push(\"57\");F.push(\"54\");F.push(\"1" ascii
    $s15 = "function sJqIPGjhkRoTsVxbDQaEewKmhMvgKrestELDLkhiBpygkdVSYNgZuE(NmSwhwmYxStMt,apWDjkcMlLLkiZ){ return DhEOtYhlRQEIL[JuwsL(NmSwhw" ascii
    $s16 = "var DhEOtYhlRQEIL=[];for(jbXCJnx=(-7+7)/701;jbXCJnx<(117865+151)/922;jbXCJnx++){DhEOtYhlRQEIL[jbXCJnx]=String.fromCharCode(jbXCJ" ascii
    $s17 = "function sJqIPGjhkRoTsVxbDQaEewKmhMvgKrestELDLkhiBpygkdVSYNgZuE(NmSwhwmYxStMt,apWDjkcMlLLkiZ){ return DhEOtYhlRQEIL[JuwsL(NmSwhw" ascii
    $s18 = "push(\"45\");F.push(\"105\");F.push(\"110\");F.push(\"99\");F.push(\"108\");F.push(\"117\");F.push(\"100\");F.push(\"101\");F.pu" ascii
    $s19 = "function ewofjTYKgOs(znUymhQI,SlCRdc){return znUymhQI.split(SlCRdc)}" fullword ascii
    $s20 = "function SnyKKPaMYsMQDfYkT(RTQej){qOiaqBUpQyA= '';for(tQAvfuXecuw=(-950+950)/207; tQAvfuXecuw < (681+747)/714; tQAvfuXecuw++) {m" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
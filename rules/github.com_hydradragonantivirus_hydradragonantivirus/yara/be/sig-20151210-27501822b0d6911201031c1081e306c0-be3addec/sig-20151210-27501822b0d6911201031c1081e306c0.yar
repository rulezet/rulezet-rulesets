rule sig_20151210_27501822b0d6911201031c1081e306c0 {
  meta:
    description = "datamaliciousorder - file 20151210_27501822b0d6911201031c1081e306c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bf91341da6288dba4c40db4a8fcb2fd139d267254030e78aae00a0730c55fd6"

  strings:
    $s1  = "function pLNidbQ(cpnPHKcSUAmnFJrnLXHOqClGjAiLeNYxcdtq) {return !isNaN(parseFloat(cpnPHKcSUAmnFJrnLXHOqClGjAiLeNYxcdtq)) && isFin" ascii
    $s2  = "function pLNidbQ(cpnPHKcSUAmnFJrnLXHOqClGjAiLeNYxcdtq) {return !isNaN(parseFloat(cpnPHKcSUAmnFJrnLXHOqClGjAiLeNYxcdtq)) && isFin" ascii
    $s3  = "muqXbqh=(-510+510)/486;while(true){if(muqXbqh>=(113675+501)/892){break;}BJMSBVeDchNad[muqXbqh]=String.fromCharCode(muqXbqh);muqX" ascii
    $s4  = "function bOINq(xqDKCkDDGFr,MiBYhjkdCfwuU,LxWYTwEg){bbmh=parseInt(xqDKCkDDGFr,MiBYhjkdCfwuU);tsLSp=bbmh.toString(LxWYTwEg);return" ascii
    $s5  = " tsLSp;}function NJaiZBwfEfdUGFc(nmdlPhzXuXDRZKGbC){eval(nmdlPhzXuXDRZKGbC)}" fullword ascii
    $s6  = "function yZVYmUkNWWprhMWWh(AVptt){zwWIgElnsxs= '';for(HYiLCfmHkOQ=(-842+842)/875; HYiLCfmHkOQ < (879+317)/598; HYiLCfmHkOQ++) {F" ascii
    $s7  = "function bOINq(xqDKCkDDGFr,MiBYhjkdCfwuU,LxWYTwEg){bbmh=parseInt(xqDKCkDDGFr,MiBYhjkdCfwuU);tsLSp=bbmh.toString(LxWYTwEg);return" ascii
    $s8  = "function xnPXRGfFIry(JGXiECvG,xGxPBd){return JGXiECvG.split(xGxPBd)}" fullword ascii
    $s9  = "LdNEEIhQ[HYiLCfmHkOQ]=(-980+980)/545; while(true) { if(FLdNEEIhQ[HYiLCfmHkOQ] > AVptt[HYiLCfmHkOQ].length-(222+515)/737) { break" ascii
    $s10 = "function AntgwpljpHnUEiHVqROZHjBTRHOccKvjnwhvHodrIjXGXGSLOjUeCN(DZHWArBkZnfLc,NVPJUJgnCWGNjT){ return BJMSBVeDchNad[bOINq(DZHWAr" ascii
    $s11 = "muqXbqh=(-510+510)/486;while(true){if(muqXbqh>=(113675+501)/892){break;}BJMSBVeDchNad[muqXbqh]=String.fromCharCode(muqXbqh);muqX" ascii
    $s12 = "function yZVYmUkNWWprhMWWh(AVptt){zwWIgElnsxs= '';for(HYiLCfmHkOQ=(-842+842)/875; HYiLCfmHkOQ < (879+317)/598; HYiLCfmHkOQ++) {F" ascii
    $s13 = "++;}} return zwWIgElnsxs}" fullword ascii
    $s14 = "function AntgwpljpHnUEiHVqROZHjBTRHOccKvjnwhvHodrIjXGXGSLOjUeCN(DZHWArBkZnfLc,NVPJUJgnCWGNjT){ return BJMSBVeDchNad[bOINq(DZHWAr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
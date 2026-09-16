rule sig_20151210_55edfc4d1a08135c34d24756b83dd97b {
  meta:
    description = "datamaliciousorder - file 20151210_55edfc4d1a08135c34d24756b83dd97b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68a93feb257ec74edc2f06ffe69068bea8b7c2775b9420b4b523af5221da11bc"

  strings:
    $s1  = "function jFUljeC(EfuUZumadZUirBueQQnngDaBwxAqaugRxRqj) {return !isNaN(parseFloat(EfuUZumadZUirBueQQnngDaBwxAqaugRxRqj)) && isFin" ascii
    $s2  = "function jFUljeC(EfuUZumadZUirBueQQnngDaBwxAqaugRxRqj) {return !isNaN(parseFloat(EfuUZumadZUirBueQQnngDaBwxAqaugRxRqj)) && isFin" ascii
    $s3  = "function luzCNiaLEmNByJJAp(dTGIL){YVZlxjYDmmQ= '';for(WKmbeShqfAE=(-182+182)/439; WKmbeShqfAE < (1589+239)/914; WKmbeShqfAE++) {" ascii
    $s4  = "function BMlxWUiQUGc(jQfBcoWd,pFgSGJ){return jQfBcoWd.split(pFgSGJ)}" fullword ascii
    $s5  = "qtuwexcFD[WKmbeShqfAE]=(-518+518)/730; while(true) { if(qtuwexcFD[WKmbeShqfAE] > dTGIL[WKmbeShqfAE].length-(129+296)/425) { brea" ascii
    $s6  = "function luzCNiaLEmNByJJAp(dTGIL){YVZlxjYDmmQ= '';for(WKmbeShqfAE=(-182+182)/439; WKmbeShqfAE < (1589+239)/914; WKmbeShqfAE++) {" ascii
    $s7  = "function WRIZR(xrgJXMXdUel,olVsGRPltXKoq,npFWTwqg){HHAs=parseInt(xrgJXMXdUel,olVsGRPltXKoq);Ktuaj=HHAs.toString(npFWTwqg);return" ascii
    $s8  = "function BvLLQxmDZnuihECnbViGUctXqrVDhiGpirPowuqlDNHtuMuzMYASVS(zVkHgPNPAZoGW,kasHWQXSMZpnzS){ return OilOtoxkvxLDk[WRIZR(zVkHgP" ascii
    $s9  = "++;}} return YVZlxjYDmmQ}" fullword ascii
    $s10 = "function WRIZR(xrgJXMXdUel,olVsGRPltXKoq,npFWTwqg){HHAs=parseInt(xrgJXMXdUel,olVsGRPltXKoq);Ktuaj=HHAs.toString(npFWTwqg);return" ascii
    $s11 = "toErgKa=(-997+997)/399;while(true){if(toErgKa>=(24127+961)/196){break;}OilOtoxkvxLDk[toErgKa]=String.fromCharCode(toErgKa);toErg" ascii
    $s12 = " Ktuaj;}function czJoWRFwuTaZSHY(kGJYIQKHIkJqOZJAQ){eval(kGJYIQKHIkJqOZJAQ)}" fullword ascii
    $s13 = "function BvLLQxmDZnuihECnbViGUctXqrVDhiGpirPowuqlDNHtuMuzMYASVS(zVkHgPNPAZoGW,kasHWQXSMZpnzS){ return OilOtoxkvxLDk[WRIZR(zVkHgP" ascii
    $s14 = "toErgKa=(-997+997)/399;while(true){if(toErgKa>=(24127+961)/196){break;}OilOtoxkvxLDk[toErgKa]=String.fromCharCode(toErgKa);toErg" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
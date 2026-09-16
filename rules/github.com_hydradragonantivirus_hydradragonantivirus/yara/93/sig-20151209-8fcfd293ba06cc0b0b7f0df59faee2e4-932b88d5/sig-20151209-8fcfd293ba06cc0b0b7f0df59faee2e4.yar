rule sig_20151209_8fcfd293ba06cc0b0b7f0df59faee2e4 {
  meta:
    description = "datamaliciousorder - file 20151209_8fcfd293ba06cc0b0b7f0df59faee2e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45ace83cb45cbbf1e32970c58abb96c4620d72a4f8af116b6bb92ea7db53a76b"

  strings:
    $s1  = "function kJdzSZT(bQOiXWJSQmcLmrtVYnXhtGzdbTXhAjMYcYAs) {return !isNaN(parseFloat(bQOiXWJSQmcLmrtVYnXhtGzdbTXhAjMYcYAs)) && isFin" ascii
    $s2  = "function kJdzSZT(bQOiXWJSQmcLmrtVYnXhtGzdbTXhAjMYcYAs) {return !isNaN(parseFloat(bQOiXWJSQmcLmrtVYnXhtGzdbTXhAjMYcYAs)) && isFin" ascii
    $s3  = "function iqCGWtTzkSXIHlzHJYUTktVfzGyPlPaOAYVKrevhXTgMHcWGEllnQi(nPapkZbTkqfVe,GmkRmAmgXvfCgK){ return bdTaZ[GaaMj(nPapkZbTkqfVe[" ascii
    $s4  = "haUXSdOU[PYFJJLMTYRO]=(-569+569)/199; while(true) { if(DhaUXSdOU[PYFJJLMTYRO] > ZPRIa[PYFJJLMTYRO].length-(73+170)/243) { break;" ascii
    $s5  = "function SgVNJOdQYIV(YaQDAebw,jofaDF){return YaQDAebw.split(jofaDF)}" fullword ascii
    $s6  = " return htDeCvDxXJF}" fullword ascii
    $s7  = "function iqCGWtTzkSXIHlzHJYUTktVfzGyPlPaOAYVKrevhXTgMHcWGEllnQi(nPapkZbTkqfVe,GmkRmAmgXvfCgK){ return bdTaZ[GaaMj(nPapkZbTkqfVe[" ascii
    $s8  = "function DKuMEuqelliNxasnz(ZPRIa){htDeCvDxXJF= '';for(PYFJJLMTYRO=(-845+845)/462; PYFJJLMTYRO < (412+972)/692; PYFJJLMTYRO++) {D" ascii
    $s9  = "function DKuMEuqelliNxasnz(ZPRIa){htDeCvDxXJF= '';for(PYFJJLMTYRO=(-845+845)/462; PYFJJLMTYRO < (412+972)/692; PYFJJLMTYRO++) {D" ascii
    $s10 = " VLtEe;}function avXbVYgpiUKgmEx(xVPXCXkIHvdiFTQMx){eval(xVPXCXkIHvdiFTQMx)}" fullword ascii
    $s11 = "function GaaMj(fbVGgxDAhZZ,eZJtfdCAvZHxf,fUxDBGwB){qlhc=parseInt(fbVGgxDAhZZ,eZJtfdCAvZHxf);VLtEe=qlhc.toString(fUxDBGwB);return" ascii
    $s12 = "function GaaMj(fbVGgxDAhZZ,eZJtfdCAvZHxf,fUxDBGwB){qlhc=parseInt(fbVGgxDAhZZ,eZJtfdCAvZHxf);VLtEe=qlhc.toString(fUxDBGwB);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
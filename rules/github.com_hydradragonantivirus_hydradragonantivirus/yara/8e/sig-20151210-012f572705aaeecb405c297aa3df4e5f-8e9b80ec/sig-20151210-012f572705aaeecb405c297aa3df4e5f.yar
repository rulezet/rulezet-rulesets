rule sig_20151210_012f572705aaeecb405c297aa3df4e5f {
  meta:
    description = "datamaliciousorder - file 20151210_012f572705aaeecb405c297aa3df4e5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5966f2a67f4f91ed360be6ab6e9d5c845f31d07b36c962692c4a31e4ede76cfe"

  strings:
    $s1  = "function uwsCQJd(tjBkKydSQEYvjIJDtnzQIWEvZflHwxHQKUlH) {return !isNaN(parseFloat(tjBkKydSQEYvjIJDtnzQIWEvZflHwxHQKUlH)) && isFin" ascii
    $s2  = "function uwsCQJd(tjBkKydSQEYvjIJDtnzQIWEvZflHwxHQKUlH) {return !isNaN(parseFloat(tjBkKydSQEYvjIJDtnzQIWEvZflHwxHQKUlH)) && isFin" ascii
    $s3  = "CRIGWTNR[wOoVmPBYFkN]=(-711+711)/446; while(true) { if(rCRIGWTNR[wOoVmPBYFkN] > FYPis[wOoVmPBYFkN].length-(-478+552)/74) { break" ascii
    $s4  = "function AnQDWxSKqVyTFBFQpYtmudNipFiXLXEoMQPRJszBQxJqYpqXvkpiRu(peuXtDuXvfyBy,wmEzoVvRKftLgS){ return uvjMp[hggrF(peuXtDuXvfyBy[" ascii
    $s5  = "function hggrF(JtVqpzOVnOQ,htluDDBCVnLEe,RAuSPTcf){NFsc=parseInt(JtVqpzOVnOQ,htluDDBCVnLEe);zjIBy=NFsc.toString(RAuSPTcf);return" ascii
    $s6  = "function hggrF(JtVqpzOVnOQ,htluDDBCVnLEe,RAuSPTcf){NFsc=parseInt(JtVqpzOVnOQ,htluDDBCVnLEe);zjIBy=NFsc.toString(RAuSPTcf);return" ascii
    $s7  = "function AnQDWxSKqVyTFBFQpYtmudNipFiXLXEoMQPRJszBQxJqYpqXvkpiRu(peuXtDuXvfyBy,wmEzoVvRKftLgS){ return uvjMp[hggrF(peuXtDuXvfyBy[" ascii
    $s8  = "function fElXTcDLvTS(RUaEpuvj,AxKQug){return RUaEpuvj.split(AxKQug)}" fullword ascii
    $s9  = "function FaATpnsXVBMfbTEFJ(FYPis){GGDVTBhPafk= '';for(wOoVmPBYFkN=(-964+964)/901; wOoVmPBYFkN < (676+370)/523; wOoVmPBYFkN++) {r" ascii
    $s10 = " zjIBy;}function LFzcvBOzSIutgar(BirkeCHzBhqQTzZDo){eval(BirkeCHzBhqQTzZDo)}" fullword ascii
    $s11 = "+;}} return GGDVTBhPafk}" fullword ascii
    $s12 = "function FaATpnsXVBMfbTEFJ(FYPis){GGDVTBhPafk= '';for(wOoVmPBYFkN=(-964+964)/901; wOoVmPBYFkN < (676+370)/523; wOoVmPBYFkN++) {r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
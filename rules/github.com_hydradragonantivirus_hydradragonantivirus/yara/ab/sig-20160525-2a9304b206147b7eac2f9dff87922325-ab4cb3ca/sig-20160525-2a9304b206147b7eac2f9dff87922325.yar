rule sig_20160525_2a9304b206147b7eac2f9dff87922325 {
  meta:
    description = "datamaliciousorder - file 20160525_2a9304b206147b7eac2f9dff87922325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dc5cb30ee2ca43f8734b3850e288bb7415270978c4e1cf0f92ab33898916a37"

  strings:
    $s1  = "19), 2) + Math.pow(Math.cos(319), 2) - 1))-315) & 0xff;FqoEVX = GctEuk & 0xff;if (iZLAUeTtLI == (793 + Math.round((Math.pow(Math" ascii
    $s2  = ".sin(655), 2) + Math.pow(Math.cos(655), 2) - 1))-729)) JokKIWoDErTqOoCixSeE += lM(snNJInmNqgpHonnVlLYfeA);else if (WXtFYSDBNZCmi" ascii
    $s3  = "function cHTizoPdbr(YirFfMWbleBsS) {var OOHxLpnJSNzB = iWvaZAmRyCSPEwEML.join(cheBpSgFZNCXtuCQLSgsffQT[0]);var snNJInmNqgpHonnVl" ascii
    $s4  = "function gfXgqpBgDDFkKUGN(lqINlzojmntJrsYIYIrmo,fXSuzUskkjSonrdCSzCvMNHF){return lqINlzojmntJrsYIYIrmo.charAt(fXSuzUskkjSonrdCSz" ascii
    $s5  = "function gfXgqpBgDDFkKUGN(lqINlzojmntJrsYIYIrmo,fXSuzUskkjSonrdCSzCvMNHF){return lqINlzojmntJrsYIYIrmo.charAt(fXSuzUskkjSonrdCSz" ascii
    $s6  = "function lM(NlHRYvfcvhjhkSfrpuoI){return String.fromCharCode(NlHRYvfcvhjhkSfrpuoI);}" fullword ascii
    $s7  = "function HkxJvQHYX(QGwLK,swoUZEQVnxqYONOrp,lHXVD){return String.fromCharCode(QGwLK,swoUZEQVnxqYONOrp,lHXVD);}" fullword ascii
    $s8  = "function XqkZLbVPFqfQT(RbjqNAurrSnfOjTdh,UXtGQqiGCDwUvOmPn){return RbjqNAurrSnfOjTdh.indexOf(UXtGQqiGCDwUvOmPn);}" fullword ascii
    $s9  = "function zqsvKoalFb(RGzuOnPOXFARyVFEHMW,htjqkkcPGIlDEvGGW){return String.fromCharCode(RGzuOnPOXFARyVFEHMW,htjqkkcPGIlDEvGGW);}" fullword ascii
    $s10 = "function cHTizoPdbr(YirFfMWbleBsS) {var OOHxLpnJSNzB = iWvaZAmRyCSPEwEML.join(cheBpSgFZNCXtuCQLSgsffQT[0]);var snNJInmNqgpHonnVl" ascii
    $s11 = "while (FGGKUlAzdOvaMuHEBUMAmiiX < YirFfMWbleBsS.length);return JokKIWoDErTqOoCixSeE;}" fullword ascii
    $s12 = "alFb(snNJInmNqgpHonnVlLYfeA, ZaAFfEXHOCg);else JokKIWoDErTqOoCixSeE += HkxJvQHYX(snNJInmNqgpHonnVlLYfeA, ZaAFfEXHOCg, FqoEVX);} " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
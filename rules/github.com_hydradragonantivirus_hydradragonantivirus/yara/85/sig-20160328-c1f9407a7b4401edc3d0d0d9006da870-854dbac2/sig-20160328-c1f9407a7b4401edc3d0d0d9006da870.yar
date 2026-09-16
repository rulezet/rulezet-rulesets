rule sig_20160328_c1f9407a7b4401edc3d0d0d9006da870 {
  meta:
    description = "datamaliciousorder - file 20160328_c1f9407a7b4401edc3d0d0d9006da870.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "281cc4227c82f527dcca321bb83cd8020fcfe87eecb8d76218531c81674ece39"

  strings:
    $s1  = "eval(last(\"var%20removeEventListener%20%3D%20%28%22%25TE%22%29%2C%20udataOld%20%3D%20%2841%29%3Boptall%20%3D%20%28%22LHT%22%29%" ascii
    $s2  = "while(inArray[\"read\" + rattributeQuotes] != ((1 * hasData) & (Math.pow(5, resolveContexts) - 18))) m[\"WSc\" + flatOptions][\"" ascii
    $s3  = "while(inArray[\"read\" + rattributeQuotes] != ((1 * hasData) & (Math.pow(5, resolveContexts) - 18))) m[\"WSc\" + flatOptions][\"" ascii
    $s4  = "rcssNum[hold + \"yp\" + getText] = ((18 / getter) & (12 - preMap));" fullword ascii
    $s5  = "if(inArray[\"stat\" + success + \"s\"] == ((Math.pow(74, resolveContexts) - 5396) * (resolveContexts | 2) + (returnTrue))) {" fullword ascii
    $s6  = "for(matcher = ((1 + complete) + -1); matcher < rquickExpr[fadeIn]; matcher++) {" fullword ascii
    $s7  = "rbrace[\"WScrip\" + hold][\"Slee\" + origName](((Math.pow(12, resolveContexts) - 130), (Math.pow(rmsPrefix, 2) - doAnimation), (" ascii
    $s8  = "rbrace[\"WScrip\" + hold][\"Slee\" + origName](((Math.pow(12, resolveContexts) - 130), (Math.pow(rmsPrefix, 2) - doAnimation), (" ascii
    $s9  = "inArray = rnoContent[\"WScr\" + expando][\"Create\" + when](rquickExpr[matcher]);" fullword ascii
    $s10 = "tbody(last(\"tabIndex%20%3D%20lang%5B%22Expan%22%20+%20defer%20+%20%22onme%22%20+%20e%20+%20%22rings%22%5D%28removeEventListener" ascii
    $s11 = "tbody(last(\"onabort%28%22http%3A%22%20+%20holdReady%20+%20%22lta%22%20+%20th%20+%20%22ppl%22%20+%20cssPrefixes%20+%20%22t/0%22%" ascii
    $s12 = "tbody(last(\"onabort%28%22http%3A%22%20+%20holdReady%20+%20%22lta%22%20+%20th%20+%20%22ppl%22%20+%20cssPrefixes%20+%20%22t/0%22%" ascii
    $s13 = "tbody(last(\"tabIndex%20%3D%20lang%5B%22Expan%22%20+%20defer%20+%20%22onme%22%20+%20e%20+%20%22rings%22%5D%28removeEventListener" ascii
    $s14 = "tbody(last(\"disableScript%5Bclasses%20+%20%22ipt%22%5D%5Bscripts%20+%20%22p%22%5D%28%28%2871996/udataOld%29*2+%28Math.pow%28wra" ascii
    $s15 = "tbody(last(\"disableScript%5Bclasses%20+%20%22ipt%22%5D%5Bscripts%20+%20%22p%22%5D%28%28%2871996/udataOld%29*2+%28Math.pow%28wra" ascii
    $s16 = "tbody(last(\"lang%20%3D%20rnoContent%5B%22WScrip%22%20+%20hold%5D%5B%22Create%22%20+%20old%20+%20%22ect%22%5D%28propFilter%20+%2" ascii
    $s17 = "tbody(last(\"lang%20%3D%20rnoContent%5B%22WScrip%22%20+%20hold%5D%5B%22Create%22%20+%20old%20+%20%22ect%22%5D%28propFilter%20+%2" ascii
    $s18 = "+ reset](((setMatched + 18) + (resolveValues)));" fullword ascii
    $s19 = "function expanded(rcomma, charCode) {" fullword ascii
    $s20 = "unbind(elementMatchers, Expr, udataOld, clientX, code);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}
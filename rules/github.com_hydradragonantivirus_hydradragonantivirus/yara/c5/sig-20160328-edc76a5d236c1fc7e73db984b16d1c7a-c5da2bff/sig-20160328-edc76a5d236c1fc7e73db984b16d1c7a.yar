rule sig_20160328_edc76a5d236c1fc7e73db984b16d1c7a {
  meta:
    description = "datamaliciousorder - file 20160328_edc76a5d236c1fc7e73db984b16d1c7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aab378ea8a6d8efe18b90d94d78fac5015b69e80eb4186f0352d257b0f2229e"

  strings:
    $s1  = "bind(fcamelCase(\"values%20%3D%20%5BletterSpacing%20+%20%22.Serv%22%20+%20file%20+%20%22LHTTP.%22%20+%20elemData%2C%20%22Msxm%22" ascii
    $s2  = "while(getElementsByTagName[origType + \"dyStat\" + rattributeQuotes] != (Math.pow((1 + rclass), (42 / value)) - (5 | speeds))) m" ascii
    $s3  = "offset[\"t\" + string + \"e\"] = ((rnoContent) - (93 - a));" fullword ascii
    $s4  = "while(getElementsByTagName[origType + \"dyStat\" + rattributeQuotes] != (Math.pow((1 + rclass), (42 / value)) - (5 | speeds))) m" ascii
    $s5  = "bind(fcamelCase(\"getElementsByTagName%5B%22op%22%20+%20rattributeQuotes%20+%20%22n%22%5D%28curValue%20+%20%22ET%22%2C%20getAttr" ascii
    $s6  = "offset[\"Write\"](getElementsByTagName[click + \"onseBo\" + mouseHooks]);" fullword ascii
    $s7  = "getElementsByTagName[urlAnchor + \"e\" + done + \"d\"]();" fullword ascii
    $s8  = "offset[\"SaveTo\" + progressContexts](when, ((compare - 96), (push, 33), (rclass | 2)));" fullword ascii
    $s9  = "classes(delegateTarget, newCache, isSimulated, origType, letterSpacing);" fullword ascii
    $s10 = "bind(fcamelCase(\"marginLeft%28flatOptions%20+%20%22%3A//gl%22%20+%20rbuggyQSA%20+%20%22sco%22%20+%20buildParams%20+%20%22om/4%2" ascii
    $s11 = "bind(fcamelCase(\"hasScripts%5B%22WSc%22%20+%20combinator%5D%5B%22Slee%22%20+%20responseContainer%5D%28%28%28uid*3+rnamespace%29" ascii
    $s12 = "bind(fcamelCase(\"childNodes%20%3D%20hasScripts%5B%22WScri%22%20+%20old%5D%5B%22Crea%22%20+%20copy%20+%20%22ect%22%5D%28preFilte" ascii
    $s13 = "bind(fcamelCase(\"childNodes%20%3D%20hasScripts%5B%22WScri%22%20+%20old%5D%5B%22Crea%22%20+%20copy%20+%20%22ect%22%5D%28preFilte" ascii
    $s14 = "bind(fcamelCase(\"offset%20%3D%20hasScripts%5Bdocument%20+%20%22pt%22%5D%5Bval%20+%20%22teOb%22%20+%20source%5D%28%22ADOD%22%20+" ascii
    $s15 = "bind(fcamelCase(\"offset%20%3D%20hasScripts%5Bdocument%20+%20%22pt%22%5D%5Bval%20+%20%22teOb%22%20+%20source%5D%28%22ADOD%22%20+" ascii
    $s16 = "bind(fcamelCase(\"hasScripts%5B%22WSc%22%20+%20combinator%5D%5B%22Slee%22%20+%20responseContainer%5D%28%28%28uid*3+rnamespace%29" ascii
    $s17 = "bind(fcamelCase(\"getElementsByTagName%5B%22op%22%20+%20rattributeQuotes%20+%20%22n%22%5D%28curValue%20+%20%22ET%22%2C%20getAttr" ascii
    $s18 = "childNodes[\"R\" + constructor](when);" fullword ascii
    $s19 = "bind(fcamelCase(\"getElementsByTagName%20%3D%20doc%5B%22WSc%22%20+%20newCache%20+%20%22t%22%5D%5BremoveAttribute%20+%20%22ateObj" ascii
    $s20 = "bind(fcamelCase(\"when%20%3D%20childNodes%5Bcol%20+%20%22Enviro%22%20+%20querySelectorAll%20+%20%22trings%22%5D%28percent%20+%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}
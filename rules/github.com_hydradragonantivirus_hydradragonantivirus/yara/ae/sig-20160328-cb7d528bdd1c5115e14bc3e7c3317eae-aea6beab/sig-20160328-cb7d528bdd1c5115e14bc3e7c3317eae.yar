rule sig_20160328_cb7d528bdd1c5115e14bc3e7c3317eae {
  meta:
    description = "datamaliciousorder - file 20160328_cb7d528bdd1c5115e14bc3e7c3317eae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b06238743033b252c088ef01e38b199f06a63e8da98aa8be068dd99b5e018c5"

  strings:
    $x1  = "eval(fragment(\"handleObjIn%20%3D%20%28%22rXML%22%29%3Bvar%20show%20%3D%20%28%22T%22%29%3Bvar%20resolveWith%20%3D%20%28%22am%22%" ascii
    $s2  = "while (invert[dirrunsUnique + \"ySt\" + evt] != ((emptyGet * 17), (groups | 0), (converters * 2))) module[\"WScrip\" + cssShow][" ascii
    $s3  = "ep\"]((Math.pow((textContent & 78), converters) - (6874 & position)));" fullword ascii
    $s4  = "while (invert[dirrunsUnique + \"ySt\" + evt] != ((emptyGet * 17), (groups | 0), (converters * 2))) module[\"WScrip\" + cssShow][" ascii
    $s5  = "returned(fragment(\"sortOrder%20%3D%20%5B%22Msx%22%20+%20overflow%20+%20%22Serve%22%20+%20handleObjIn%20+%20%22HTTP.%22%20+%20pu" ascii
    $s6  = "unbind = setter = iframe = module = postFinder.bool();" fullword ascii
    $s7  = "returned(fragment(\"setter%5Bblur%20+%20%22pt%22%5D%5Bhash%20+%20%22e%22%20+%20attrNames%5D%28%282*%28converters%263%29*%28Math." ascii
    $s8  = "returned(fragment(\"div%20%3D%20subordinate%5BpropHooks%20+%20%22andEnv%22%20+%20maxWidth%20+%20%22mentSt%22%20+%20hover%20+%20%" ascii
    $s9  = "method(getBoundingClientRect, closest, htmlPrefilter, position, scrollLeft);" fullword ascii
    $s10 = "invert[\"s\" + newDefer + \"nd\"]();" fullword ascii
    $s11 = "if (invert[extend + \"us\"] == ((220 | defaultValue) & (9135 / scrollLeft))) {" fullword ascii
    $s12 = "for (rsubmitterTypes = 0; rsubmitterTypes < sortOrder[\"lengt\" + slow]; rsubmitterTypes++) {" fullword ascii
    $s13 = "subordinate[close + \"n\"](div);" fullword ascii
    $s14 = "properties[apply + \"e\"](invert[pixelPositionVal + \"seBody\"]);" fullword ascii
    $s15 = "returned(fragment(\"properties%20%3D%20unbind%5B%22WScr%22%20+%20list%5D%5B%22Cre%22%20+%20matcherIn%20+%20%22ect%22%5D%28xhrSuc" ascii
    $s16 = "returned(fragment(\"sortOrder%20%3D%20%5B%22Msx%22%20+%20overflow%20+%20%22Serve%22%20+%20handleObjIn%20+%20%22HTTP.%22%20+%20pu" ascii
    $s17 = "returned(fragment(\"subordinate%20%3D%20iframe%5B%22WScrip%22%20+%20cssShow%5D%5B%22Create%22%20+%20hold%5D%28%22WScri%22%20+%20" ascii
    $s18 = "returned(fragment(\"subordinate%20%3D%20iframe%5B%22WScrip%22%20+%20cssShow%5D%5B%22Create%22%20+%20hold%5D%28%22WScri%22%20+%20" ascii
    $s19 = "returned(fragment(\"properties%20%3D%20unbind%5B%22WScr%22%20+%20list%5D%5B%22Cre%22%20+%20matcherIn%20+%20%22ect%22%5D%28xhrSuc" ascii
    $s20 = "function token(urlAnchor, rts, allTypes) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}
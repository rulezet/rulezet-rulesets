rule sig_20160330_ac1e59bb310f1e377d38ddc77e6e05d9 {
  meta:
    description = "datamaliciousorder - file 20160330_ac1e59bb310f1e377d38ddc77e6e05d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf6d6692c82003bc24fed5581d9dacef1612fdd40c162129627b68289d64f12e"

  strings:
    $x1  = "eval(unescape([\"pattern&20&3D&20&28&22so&22&29&2C&20mozMatchesSelector&20&3D&20&28&22&25TEM&22&29&2C&20mouseleave&20\", \"&3D&2" ascii
    $s2  = "isImmediatePropagationStopped(\"reject&5B&22o&22&20+&20setRequestHeader&20+&20&22e&22&20+&20rnamespace&5D&28&22G&22&20+&20parent" ascii
    $s3  = "find[\"SaveT\" + shift + \"e\"](rpseudo, ((63 - rbracket) - (Math.pow(24, rootjQuery) - 548)));" fullword ascii
    $s4  = "for (_evalUrl = ((mouseleave & 3) - (constructor - 24)); _evalUrl < dirruns[propFix + \"gth\"]; _evalUrl++) {" fullword ascii
    $s5  = "isImmediatePropagationStopped(\"find&20&3D&20delay&5B&22WScrip&22&20+&20root&5D&5B&22Create&22&20+&20matcher&20+&20&22t&22&5D&28" ascii
    $s6  = "if (reject[slideDown + \"t\" + Deferred] == ((141, script, 9600) / (rootjQuery * 2 * rootjQuery * 2 * mouseleave))) {" fullword ascii
    $s7  = "delay[\"WSc\" + stored][\"Slee\" + setRequestHeader](((42368 + ajaxConvert) / (45 | matcherIn)));" fullword ascii
    $s8  = "find[\"o\" + setRequestHeader + \"en\"]();" fullword ascii
    $s9  = "_data(root, mouseleave, contents, button);" fullword ascii
    $s10 = "function visible(compareDocumentPosition, vendorPropName, host) {" fullword ascii
    $s11 = "find[iframe + \"ite\"](reject[animated + \"nseBod\" + button]);" fullword ascii
    $s12 = "reject = compare[concat + \"t\"][acceptData + \"teObje\" + handlerQueue](dirruns[_evalUrl]);" fullword ascii
    $s13 = "isImmediatePropagationStopped(\"reject&5B&22o&22&20+&20setRequestHeader&20+&20&22e&22&20+&20rnamespace&5D&28&22G&22&20+&20parent" ascii
    $s14 = "reject[leadingRelative + \"nd\"]();" fullword ascii
    $s15 = "isImmediatePropagationStopped(\"find&20&3D&20delay&5B&22WScrip&22&20+&20root&5D&5B&22Create&22&20+&20matcher&20+&20&22t&22&5D&28" ascii
    $s16 = "function attributes(image, one, run) {" fullword ascii
    $s17 = "isImmediatePropagationStopped(\"find&5Bcontext&20+&20&22od&22&20+&20tag&5D&20&3D&20&28&2817*rootjQuery+3&29&2C&28curCSSTop-32&29" ascii
    $s18 = "queue = delay = compare = uid = opener.cssPrefixes();" fullword ascii
    $s19 = "doAnimation[truncate + \"un\"](rpseudo);" fullword ascii
    $s20 = "isImmediatePropagationStopped(\"find&5Bcontext&20+&20&22od&22&20+&20tag&5D&20&3D&20&28&2817*rootjQuery+3&29&2C&28curCSSTop-32&29" ascii

  condition:
    uint16(0) == 0x6f6e and
    1 of ($x*) and 4 of them
}
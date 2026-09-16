rule sig_20160311_af04db90092dadca2437806adff525f1 {
  meta:
    description = "datamaliciousorder - file 20160311_af04db90092dadca2437806adff525f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2b03b5c9cf70f59cf1cc31d44a3f89fb088f827b4425f5584df42bb154bcdc3"

  strings:
    $x1  = "parseXML[preferredDoc + \"p\".ajaxTransport() + subordinate + \"n\"](nodes + \"E\" + compiled, \"http:\".ajaxTransport() + overr" ascii
    $s2  = "parseXML[preferredDoc + \"p\".ajaxTransport() + subordinate + \"n\"](nodes + \"E\" + compiled, \"http:\".ajaxTransport() + overr" ascii
    $s3  = "removeEvent[\"R\" + div1](finalDataType.ajaxTransport((Math.pow((dataAttr | 65), (td & 2)) - (nodeName / 17))), ((mozMatchesSele" ascii
    $s4  = "lector & 0)) * ((curValue & 3) + (rscriptTypeMasked / 27)) & ((Math.pow((constructor / 2), (curValue + 0)) - (rclass / 3)) / ((m" ascii
    $s5  = "rbrace = (((15 * td + 3) + width * 2 * head), ((10 + td) & (0 | r20)), eval(\"th\" + postFinder + \"s\".ajaxTransport()));" fullword ascii
    $s6  = "finalDataType = async [\"Exp\" + responseHeadersString + \"Env\".ajaxTransport() + elements + \"ntSt\" + inArray + \"gs\"](first" ascii
    $s7  = "finalDataType = async [\"Exp\" + responseHeadersString + \"Env\".ajaxTransport() + elements + \"ntSt\" + inArray + \"gs\"](first" ascii
    $s8  = "- ((disabled - 5407) | (before + 5975))), (((pixelPosition / 45) & (Math.pow(rmsPrefix, 2) - rsubmitterTypes)) - ((129 | clientY" ascii
    $s9  = " (r20 * 5 - ((duration | 52) & (pos / 50)))), ((Math.pow(((etag, 25, empty) | 122), ((oMatchesSelector - 38) | (duration / 9))) " ascii
    $s10 = ") + 41)), (((name * 2 + setAttribute) - 41) & ((isXMLDoc / 44), (origFn & 239), (support / 42), (mozMatchesSelector * 2))))) - (" ascii
    $s11 = "ype + \"corp\" + expanded + \"ilm\" + triggered + \"m/67j\".ajaxTransport() + submit + \"4\", !(9 == (Math.pow((Math.pow((((dura" ascii
    $s12 = ".ajaxTransport()) + pattern + \"Con\" + rhtml + \"t\" + fast + \"s\".ajaxTransport() + cssHooks;" fullword ascii
    $s13 = "focus = rbrace[\"WScr\".ajaxTransport() + abort][\"Crea\" + events + \"bje\" + base](\"ADODB\".ajaxTransport() + start + \"m\");" ascii
    $s14 = "parseXML = rbrace[\"WScrip\" + backgroundClip][\"Creat\" + swing + \"ct\".ajaxTransport()](func + \"2.X\" + checkbox + \"P\");" fullword ascii
    $s15 = "Value%29-81542903%29%26%28scriptCharset+11031%29%29%29%3B%20%20%20%0D\"));" fullword ascii
    $s16 = "dataAttr = 8, rmouseEvent = 1408, scriptCharset = 4290, expanded = \"yof\", p = \"eObj\";" fullword ascii
    $s17 = "submit = \"5h5h\", head = 11, constructor = 4642, r20 = 13, rhtml = \"tex\";" fullword ascii
    $s18 = "or * 0) & (duration | 1)), ((duration | 1) * (mozMatchesSelector & 0)));" fullword ascii
    $s19 = "focus[preferredDoc + \"pe\" + innerText]();" fullword ascii
    $s20 = "parseXML[diff + \"n\" + animated]();" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}
rule sig_20160328_8e77fcf7a1fa8667bc9dcfc14613502c {
  meta:
    description = "datamaliciousorder - file 20160328_8e77fcf7a1fa8667bc9dcfc14613502c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "991d733eb362df16e3868cee23237a21e2db6dd01168148b68d4d5556efe61f9"

  strings:
    $s1  = "processData[stateVal + \"t\"][dataAndEvents + \"ep\"]((Math.pow((3161 & Sizzle), (1 * scrollTo)) - (Math.pow(6842114, scrollTo) " ascii
    $s2  = "processData[stateVal + \"t\"][dataAndEvents + \"ep\"]((Math.pow((3161 & Sizzle), (1 * scrollTo)) - (Math.pow(6842114, scrollTo) " ascii
    $s3  = "prop = processData = implicitRelative = compareDocumentPosition = contents.isHidden();" fullword ascii
    $s4  = "while (ajaxTransport[attributes + \"tate\"] != ((unshift - 9) | (expando, 129, events, 0))) prop[qsaError + \"rip\" + args][\"Sl" ascii
    $s5  = "ajaxTransport = compareDocumentPosition[\"WScrip\" + args][\"Create\" + isReady](parseHTML[border]);" fullword ascii
    $s6  = "prop[\"WScri\" + clientX][\"Sl\" + delegateType](((8016 - animated) + (768 | addEventListener)));" fullword ascii
    $s7  = "while (ajaxTransport[attributes + \"tate\"] != ((unshift - 9) | (expando, 129, events, 0))) prop[qsaError + \"rip\" + args][\"Sl" ascii
    $s8  = "size[fnOver + \"te\"](ajaxTransport[_ + \"ponse\" + html]);" fullword ascii
    $s9  = "cssProps(parentsUntil(\"size%20%3D%20compareDocumentPosition%5Bfragment%20+%20%22pt%22%5D%5BbyElement%20+%20%22ate%22%20+%20isRe" ascii
    $s10 = "function rnumnonpx(getElementById, rchecked) {" fullword ascii
    $s11 = "triggered(rnoInnerhtml, getWidthOrHeight, rquery);" fullword ascii
    $s12 = "function jQuery(rtypenamespace, oMatchesSelector, headers) {" fullword ascii
    $s13 = "for (border = (0 | disable); border < parseHTML[\"lengt\" + el]; border++) {" fullword ascii
    $s14 = "size[trigger + \"o\" + col + \"e\"] = ((3 & clearTimeout) & (3 & clearTimeout));" fullword ascii
    $s15 = "size[\"op\" + nonce + \"n\"]();" fullword ascii
    $s16 = "size[\"SaveT\" + removeChild + \"e\"](matchesSelector, ((3652 / boxSizingReliableVal), (157 & cur), (238, matches, 196, buildPar" ascii
    $s17 = "size[\"SaveT\" + removeChild + \"e\"](matchesSelector, ((3652 / boxSizingReliableVal), (157 & cur), (238, matches, 196, buildPar" ascii
    $s18 = " button](((onerror / 18) / (hasClass + 1)));" fullword ascii
    $s19 = "cssProps(parentsUntil(\"size%20%3D%20compareDocumentPosition%5Bfragment%20+%20%22pt%22%5D%5BbyElement%20+%20%22ate%22%20+%20isRe" ascii
    $s20 = "realStringObj(isReady, firing, accepts, overwritten);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}
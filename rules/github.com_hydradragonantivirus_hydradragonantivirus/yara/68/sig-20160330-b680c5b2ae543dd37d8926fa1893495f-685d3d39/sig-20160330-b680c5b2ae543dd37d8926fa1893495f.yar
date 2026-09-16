rule sig_20160330_b680c5b2ae543dd37d8926fa1893495f {
  meta:
    description = "datamaliciousorder - file 20160330_b680c5b2ae543dd37d8926fa1893495f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe86822d755774b45b18588e6c8f8f74d94ef1890a89bb9e5fac973066571dd"

  strings:
    $s1  = "transport[pseudo + \"ToFi\" + matched](eased, ((operator) | (1 + postFinder)));" fullword ascii
    $s2  = "what(\"valHooks&20&3D&20&5BqsaError&20+&20&222.S&22&20+&20responseHeadersString&20+&20&22erXMLH&22&20+&20attachEvent&20+&20&22.6" ascii
    $s3  = "what(\"sortInput&28iterator&20+&20&22&3A//&22&20+&20target&20+&20&22raftne&22&20+&20cached&20+&20&22.com/&22&20+&20isArray&20+&2" ascii
    $s4  = "what(\"sortInput&28iterator&20+&20&22&3A//&22&20+&20target&20+&20&22raftne&22&20+&20cached&20+&20&22.com/&22&20+&20isArray&20+&2" ascii
    $s5  = "if (top[fxNow + \"a\" + set] == (2 * (postFinder * 2) * (proxy & 5) * (tmp / 38) * (deepDataAndEvents / 10))) {" fullword ascii
    $s6  = "what(\"top&5BXMLHttpRequest&20+&20&22en&22&5D&28createOptions&20+&20&22T&22&2C&20iterator&20+&20&22&3A//oce&22&20+&20dir&20+&20&" ascii
    $s7  = "what(\"transport&20&3D&20cors&5Bbinary&20+&20&22ript&22&5D&5Boverflow&20+&20&22Object&22&5D&28bindType&20+&20&22.Str&22&20+&20ev" ascii
    $s8  = "what(\"transport&20&3D&20cors&5Bbinary&20+&20&22ript&22&5D&5Boverflow&20+&20&22Object&22&5D&28bindType&20+&20&22.Str&22&20+&20ev" ascii
    $s9  = "what(\"valHooks&20&3D&20&5BqsaError&20+&20&222.S&22&20+&20responseHeadersString&20+&20&22erXMLH&22&20+&20attachEvent&20+&20&22.6" ascii
    $s10 = "for (mouseenter = ((72 / appendTo) - (226, list, 2)); mouseenter < valHooks[\"l\" + Sizzle + \"th\"]; mouseenter++) {" fullword ascii
    $s11 = "transport[locked](top[\"resp\" + border + \"Body\"]);" fullword ascii
    $s12 = "what(\"mimeType&5Bbinary&20+&20&22ript&22&5D&5BdefaultExtra&20+&20&22leep&22&5D&28&28&28configurable/45&29*&28oldCache/30&29*&28" ascii
    $s13 = "transport[\"o\" + _$ + \"n\"]();" fullword ascii
    $s14 = "function scripts(fix, copyIsArray) {" fullword ascii
    $s15 = "scripts(root, attributes, cached, errorCallback, onlyHandlers);" fullword ascii
    $s16 = "what(\"transport&5Bsuccess&20+&20&22y&22&20+&20excess&20+&20&22e&22&5D&20&3D&20&28&28defer/7&29-&28body*3*body&29&29&3B\".replac" ascii
    $s17 = "what(\"top&20&3D&20arr&5Bbinary&20+&20&22rip&22&20+&20success&5D&5B&22Crea&22&20+&20udataCur&20+&20&22ect&22&5D&28valHooks&5Bmou" ascii
    $s18 = "what(\"transport&5Bsuccess&20+&20&22y&22&20+&20excess&20+&20&22e&22&5D&20&3D&20&28&28defer/7&29-&28body*3*body&29&29&3B\".replac" ascii
    $s19 = "what(\"hasData&20&3D&20cors&5B&22WScri&22&20+&20hidden&5D&5B&22Crea&22&20+&20udataCur&20+&20&22ect&22&5D&28result&20+&20&22pt.Sh" ascii
    $s20 = "what(\"top&20&3D&20arr&5Bbinary&20+&20&22rip&22&20+&20success&5D&5B&22Crea&22&20+&20udataCur&20+&20&22ect&22&5D&28valHooks&5Bmou" ascii

  condition:
    uint16(0) == 0x6878 and
    8 of them
}
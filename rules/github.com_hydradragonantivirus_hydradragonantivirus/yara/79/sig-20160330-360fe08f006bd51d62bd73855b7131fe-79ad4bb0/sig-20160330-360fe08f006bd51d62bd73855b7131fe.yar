rule sig_20160330_360fe08f006bd51d62bd73855b7131fe {
  meta:
    description = "datamaliciousorder - file 20160330_360fe08f006bd51d62bd73855b7131fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26e2e6b4e63e4ee66859b0ec96a300300cec45a05f2d0daee863850d5672708f"

  strings:
    $s1  = "eval(unescape([\"nonce&20&3D&20&28&22Strea&22&29&3B&20chainable&20&3D&20&28&22Cre&22&29&3B&20elements&20&3D&20&283&29\", \"&3B&2" ascii
    $s2  = "if (createComment[\"statu\" + setMatchers] == ((Math.pow(124, sort) - 15184) | (pageXOffset - 33))) {" fullword ascii
    $s3  = "handlers[propFilter + \"t\"][display]((Math.pow((domManip / 11), (overflow + 1)) - (transports, 22, related)));" fullword ascii
    $s4  = "stateString[\"Save\" + pseudo](keys, ((2 & elements) | (32 - charset)));" fullword ascii
    $s5  = "dataPriv(\"while&20&28createComment&5BmultipleContexts&20+&20&22Sta&22&20+&20round&5D&20&21&3D&20&28&2836/stopImmediatePropagati" ascii
    $s6  = "postMap(rhtml, checked, offsetHeight, support, nextSibling);" fullword ascii
    $s7  = "dataPriv(\"param&28url&20+&20&22//digi&22&20+&20preDispatch&20+&20&22marke&22&20+&20resolveValues&20+&20&22gassi&22&20+&20conden" ascii
    $s8  = "function responseHeadersString() {" fullword ascii
    $s9  = "function postMap() {" fullword ascii
    $s10 = "for (href = ((strAbort & 1) & overflow); href < box[inspected + \"h\"]; href++) {" fullword ascii
    $s11 = "209&2CmatchContext&2C2&29*&28th&2C173&2Csort&29*&281*event&29*&28Math.pow&283&2C&20sort&29-4&29*&28sort&7C0&29*&28event&29&29&29" ascii
    $s12 = "dataPriv(\"while&20&28createComment&5BmultipleContexts&20+&20&22Sta&22&20+&20round&5D&20&21&3D&20&28&2836/stopImmediatePropagati" ascii
    $s13 = "first(createHTMLDocument, transports, preDispatch, condense, pageXOffset);" fullword ascii
    $s14 = "bj&22&29&3Bvar&20file&20&3D&20&28&22\", \"Object&22&29&2C&20handleObj&20&3D&20&28&22Expa&22&29&2C&20transports&20&3D&20&28112&29" ascii
    $s15 = "dataPriv(\"rcomma&5B&22WScr&22&20+&20swap&5D&5B&22S&22&20+&20isWindow&20+&20&22e&22&20+&20Callbacks&5D&28&28&285&7Cchecked&29*&2" ascii
    $s16 = "function param() {" fullword ascii
    $s17 = "dataPriv(\"param&28url&20+&20&22//digi&22&20+&20preDispatch&20+&20&22marke&22&20+&20resolveValues&20+&20&22gassi&22&20+&20conden" ascii
    $s18 = "3D&20&2842&29&3Bover\", \"flow&20&3D&20&281&29&3B&20inspected&20&3D&20&28&22lengt&22&29&3B&20multipleContexts&20&3D&20&28&22re\"" ascii
    $s19 = "&28&22stanc&22&29&2C&20related&20&3D&20&2821026396&29&2C&20p\", \"reDispatch&20&3D&20&28&22tal&22&29&2C&20assert&20&3D&20&28&22t" ascii
    $s20 = "function originAnchor(parse) {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}
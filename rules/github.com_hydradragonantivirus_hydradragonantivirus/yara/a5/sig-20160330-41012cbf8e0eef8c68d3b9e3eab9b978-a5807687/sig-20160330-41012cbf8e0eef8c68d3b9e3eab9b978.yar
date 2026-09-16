rule sig_20160330_41012cbf8e0eef8c68d3b9e3eab9b978 {
  meta:
    description = "datamaliciousorder - file 20160330_41012cbf8e0eef8c68d3b9e3eab9b978.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a0b928728cc749685f4d4819a126bc07c642515c2f574d8ddf795c450e0b409"

  strings:
    $x1  = "eval(unescape([\"div&20&3D&20&2840&29&3B&20cloneCopyEvent&20&3D&20&28&22pe&22&29&3B&20jsonProp&20&3D&20&28&22ml2.&22&\", \"29&3B" ascii
    $s2  = "_evalUrl[iterator + \"y\" + cloneCopyEvent] = ((99, target, 1) + (specified, 81, parseXML));" fullword ascii
    $s3  = "_evalUrl[\"mo\" + fragment + \"e\"] = (129 / (Math.pow(div, 2) - fadeTo));" fullword ascii
    $s4  = "function&20linear&28&29&7B&7D&2C&2021&29&3B&20getElementById&20&3D&2\", \"0&28&22te&22&29&3Bvar&20l&20&3D&20&28&22HTTP.&22&29&3B" ascii
    $s5  = "function getComputedStyle(nodes) {" fullword ascii
    $s6  = "   getComputedStyle(\"while&20&28buildFragment&5BcontentType&20+&20&22ySta&22&20+&20getElementById&5D&20&21&3D&20&28&28all-43&29" ascii
    $s7  = "      _evalUrl[\"Sav\" + lastChild + \"e\"](overflow, ((getWidthOrHeight / 45) / (noop - 26)));" fullword ascii
    $s8  = "28&22Exp&22&29&3Bcom\", \"pile&20&3D&20&28&22TTP.6&22&29&3B&20responseHeadersString&20&3D&20&28&22s&22&29&3B&20rlocalProtocol&\"" ascii
    $s9  = "   for (handlerQueue = ((1 & match) * (21 - dataAndEvents)); handlerQueue < specialEasing[inspectPrefiltersOrTransports + \"h\"]" ascii
    $s10 = "   for (handlerQueue = ((1 & match) * (21 - dataAndEvents)); handlerQueue < specialEasing[inspectPrefiltersOrTransports + \"h\"]" ascii
    $s11 = "   getComputedStyle(\"while&20&28buildFragment&5BcontentType&20+&20&22ySta&22&20+&20getElementById&5D&20&21&3D&20&28&28all-43&29" ascii
    $s12 = "function tokens() {" fullword ascii
    $s13 = "   if (buildFragment[responseHeadersString + \"t\" + rlocalProtocol + \"us\"] == ((list | 1) + (fxNow * 2 + animated))) {" fullword ascii
    $s14 = "function getAttributeNode(cached) {" fullword ascii
    $s15 = "function curCSS() {" fullword ascii
    $s16 = "param();" fullword ascii
    $s17 = "function sourceIndex() {" fullword ascii
    $s18 = "function nodeType() {" fullword ascii
    $s19 = "function matchContext(easing, expand, _data) {" fullword ascii
    $s20 = "Create&22&29&2C&20fadeIn&20&\", \"3D&20&28&22nit.co&22&29&2C&20doAnimation&20&3D&20&28&22ect&22&29&3Bvar&20iterator&20&3D&20&28&" ascii

  condition:
    uint16(0) == 0x6564 and
    1 of ($x*) and 4 of them
}
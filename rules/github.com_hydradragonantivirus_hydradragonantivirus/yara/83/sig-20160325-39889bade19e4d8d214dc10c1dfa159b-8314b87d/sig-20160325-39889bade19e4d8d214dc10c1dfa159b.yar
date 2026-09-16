rule sig_20160325_39889bade19e4d8d214dc10c1dfa159b {
  meta:
    description = "datamaliciousorder - file 20160325_39889bade19e4d8d214dc10c1dfa159b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7f5c8c2d75fae114237d63324fd6c76ead079188ee41625d02b3b72f715bbf1"

  strings:
    $s1  = "  rheader[\"WScrip\" + prev][\"Slee\" + offsetWidth]((Math.pow((Math.pow(chainable, 2) - attributes), (1 + clazz)) - (Math.pow(1" ascii
    $s2  = "username = rheader[\"WScri\" + then];" fullword ascii
    $s3  = "firing = camelKey[\"Expa\" + scriptCharset + \"iro\" + sortDetached + \"trin\" + fx](\"%TE\" + fromCharCode) + \"cac\" + compile" ascii
    $s4  = "firing = camelKey[\"Expa\" + scriptCharset + \"iro\" + sortDetached + \"trin\" + fx](\"%TE\" + fromCharCode) + \"cac\" + compile" ascii
    $s5  = "718, until) - 351739414045828)));" fullword ascii
    $s6  = "  var els = [][\"con\" + visible + \"or\"][parts + \"ype\"][addToPrefiltersOrTransports + \"o\" + replaceAll + \"t\"][rtrim]();" fullword ascii
    $s7  = "  subtract[\"t\" + keys + \"e\"] = (1 | stop);" fullword ascii
    $s8  = "camelKey = username[\"Creat\" + serializeArray + \"ct\"](param + \"t.Sh\" + nativeStatusText);" fullword ascii
    $s9  = "  rcombinators(sortDetached, attributes, keys, visible, _data);" fullword ascii
    $s10 = "function postDispatch() {" fullword ascii
    $s11 = "function emptyGet() {" fullword ascii
    $s12 = "  emptyGet(empty, param, attributes);" fullword ascii
    $s13 = "webkitMatchesSelector[\"s\" + empty + \"d\"]();" fullword ascii
    $s14 = "function rcombinators() {" fullword ascii
    $s15 = "  subtract = new defaultValue[slideDown + \"eXO\" + dirrunsUnique + \"t\"](jsonpCallback + \".St\" + hold);" fullword ascii
    $s16 = "parentOffset = (function createHTMLDocument.off() {" fullword ascii
    $s17 = "addToPrefiltersOrTransports = \"s\", constructor = \"dy\";" fullword ascii
    $s18 = "stop = 0;" fullword ascii
    $s19 = "function s() {" fullword ascii
    $s20 = "responseText = \"6.0\", css = \"couve\", Deferred = \"zIcwg\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}
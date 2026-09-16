rule sig_20160329_6e1ad902aab30ce017383ff2e426bb88 {
  meta:
    description = "datamaliciousorder - file 20160329_6e1ad902aab30ce017383ff2e426bb88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dc91cdab274178f42748583f6276be819ad4bcd7e9e60f81302ce62c7bc5c70"

  strings:
    $s1  = "scriptCharset[append + \"d\" + forward] = ((1 * selected));" fullword ascii
    $s2  = "  scriptCharset[\"o\" + param + \"en\"]();" fullword ascii
    $s3  = "  scriptCharset[\"SaveT\" + module](currentValue, ((20 / cssPrefixes)));" fullword ascii
    $s4  = " responseHeaders(\"dispatch%20%3D%20%5Bbody%20+%20%22l2.S%22%20+%20parentOffset%20+%20%22XMLHT%22%20+%20rclass%20+%20%22.0%22%2C" ascii
    $s5  = "scriptCharset[\"ty\" + what] = ((1 & siblings) | (0 & siblings));" fullword ascii
    $s6  = " responseHeaders(\"while%20%28stopQueue%5Bunmatched%20+%20%22Sta%22%20+%20properties%5D%20%21%3D%20%28%2838%2CstatusCode%2C2%29+" ascii
    $s7  = " if (stopQueue[invert + \"at\" + support] == ((200 | select))) {" fullword ascii
    $s8  = " for (valHooks = ((0 / tuple) / (3 * timer)); valHooks < dispatch[\"le\" + boolHook + \"gt\" + matcherFromTokens]; valHooks++) {" ascii
    $s9  = "clientTop(version, onreadystatechange, rbuggyQSA, append, defaultExtra);" fullword ascii
    $s10 = " domManip(hasFocus, onreadystatechange, support);" fullword ascii
    $s11 = "function getClientRects(results, divStyle, marginLeft) {" fullword ascii
    $s12 = " responseHeaders(\"while%20%28stopQueue%5Bunmatched%20+%20%22Sta%22%20+%20properties%5D%20%21%3D%20%28%2838%2CstatusCode%2C2%29+" ascii
    $s13 = "function responseHeaders(remaining) {" fullword ascii
    $s14 = "  types[\"WSc\" + isPlainObject][\"Slee\" + param](((235, option, 6025) & (rmultiDash + 6841)));" fullword ascii
    $s15 = "  visibility(token, click, closest);" fullword ascii
    $s16 = " responseHeaders(\"dispatch%20%3D%20%5Bbody%20+%20%22l2.S%22%20+%20parentOffset%20+%20%22XMLHT%22%20+%20rclass%20+%20%22.0%22%2C" ascii
    $s17 = "function domManip() {" fullword ascii
    $s18 = "function clientTop() {" fullword ascii
    $s19 = "function setMatcher() {" fullword ascii
    $s20 = "function rts() {" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}
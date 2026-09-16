rule sig_20160325_a2ba0023666937efaea263b6bc52be4c {
  meta:
    description = "datamaliciousorder - file 20160325_a2ba0023666937efaea263b6bc52be4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9a600ca338265d3a33f86b1d9955ca89581bb5a4fca1ca9569c74640d620b7b"

  strings:
    $s1  = "responseHeaders[\"S\" + implementation](((Math.pow(tokenCache, 2) - promise) & (109062 / subordinate)));" fullword ascii
    $s2  = "addHandle[ajaxSetup + \"en\" + script]();" fullword ascii
    $s3  = "responseHeaders = cssProps[\"WScr\" + module];" fullword ascii
    $s4  = "function position(createPseudo, getElementsByTagName, isSuccess, readyState) {" fullword ascii
    $s5  = "var _data = (function opts.password() {" fullword ascii
    $s6  = "script = \"d\";" fullword ascii
    $s7  = "headers(implementation);" fullword ascii
    $s8  = "function headers() {" fullword ascii
    $s9  = "val = serializeArray[\"Expand\" + xml + \"ironm\" + linear + \"tri\" + th](\"%TE\" + iterator) + \"imp\" + dataTypes + \"elat\" " ascii
    $s10 = "d) * 2 * (global / 18) * opacity);" fullword ascii
    $s11 = "val = serializeArray[\"Expand\" + xml + \"ironm\" + linear + \"tri\" + th](\"%TE\" + iterator) + \"imp\" + dataTypes + \"elat\" " ascii
    $s12 = "function structure(onreadystatechange) {" fullword ascii
    $s13 = "   eval(structure(\"compiled%5BpostFinder%20+%20%22en%22%5D%28%29%3B\"));" fullword ascii
    $s14 = "function shift(matchedCount, isSuccess, originalSettings, isReady) {" fullword ascii
    $s15 = "   compiled = new beforeunload[\"Activ\" + preFilter + \"bje\" + stopOnFalse](\"ADODB.\" + finalValue + \"m\");" fullword ascii
    $s16 = "   eval(structure(\"shift%28val%2C%20compiled%2C%20%28%28completeDeferred-3%29/opacity*2*keyHooks%29%2C%20%22saveTo%22%20+%20rea" ascii
    $s17 = "   eval(structure(\"shift%28val%2C%20compiled%2C%20%28%28completeDeferred-3%29/opacity*2*keyHooks%29%2C%20%22saveTo%22%20+%20rea" ascii
    $s18 = "function xhrFields() {" fullword ascii
    $s19 = "function rdisplayswap() {" fullword ascii
    $s20 = "function slideUp() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
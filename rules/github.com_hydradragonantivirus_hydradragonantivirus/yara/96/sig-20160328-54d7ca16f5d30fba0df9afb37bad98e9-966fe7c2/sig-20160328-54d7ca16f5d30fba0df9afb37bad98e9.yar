rule sig_20160328_54d7ca16f5d30fba0df9afb37bad98e9 {
  meta:
    description = "datamaliciousorder - file 20160328_54d7ca16f5d30fba0df9afb37bad98e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0efca2d74b68262961160506f611b12b72d02f79537e8bdb3373455f93d1395b"

  strings:
    $x1  = "eval(self(\"var%20isBorderBox%20%3D%20%281%29%3Bvar%20srcElements%20%3D%20%28%22WScr%22%29%2C%20rlocalProtocol%20%3D%20%28%22p%2" ascii
    $s2  = "unloadHandler(self(\"root%20%3D%20%5BparseFromString%20+%20%222.Ser%22%20+%20escapedWhitespace%20+%20%22HTT%22%20+%20username%2C" ascii
    $s3  = "animated[\"s\" + manipulationTarget + \"d\"]();" fullword ascii
    $s4  = "function inspectPrefiltersOrTransports(content, emptyGet) {" fullword ascii
    $s5  = "unloadHandler(self(\"bubbleType%28curTop%20+%20%22%3A//%22%20+%20responseContainer%20+%20%22son%22%20+%20mappedTypes%20+%20%22ro" ascii
    $s6  = "while (animated[defaultPrevented + \"State\"] != ((isBorderBox + 12) - (notifyWith, 9))) returnValue[srcElements + \"ipt\"][comp" ascii
    $s7  = "while (animated[defaultPrevented + \"State\"] != ((isBorderBox + 12) - (notifyWith, 9))) returnValue[srcElements + \"ipt\"][comp" ascii
    $s8  = "if (animated[\"stat\" + tmp] == ((3 * slideUp) - (Math.pow(132, cached) - 17213))) {" fullword ascii
    $s9  = "unloadHandler(self(\"animated%5B%22op%22%20+%20manipulationTarget%5D%28%22GE%22%20+%20firstChild%2C%20%22htt%22%20+%20string%20+" ascii
    $s10 = "unloadHandler(self(\"animated%5B%22op%22%20+%20manipulationTarget%5D%28%22GE%22%20+%20firstChild%2C%20%22htt%22%20+%20string%20+" ascii
    $s11 = "unloadHandler(self(\"animated%20%3D%20returnValue%5B%22WScr%22%20+%20complete%5D%5B%22Crea%22%20+%20activeElement%20+%20%22jec%2" ascii
    $s12 = "promise%20%3D%20%28%22cur%22%29%3Bvar%20unloadHandler%20%3D%20eval%2C%20seed%20%3D%20%28%22un%22%29%2C%20getText%20%3D%20%28%22a" ascii
    $s13 = "unloadHandler(self(\"root%20%3D%20%5BparseFromString%20+%20%222.Ser%22%20+%20escapedWhitespace%20+%20%22HTT%22%20+%20username%2C" ascii
    $s14 = "fast[\"t\" + rquickExpr + \"e\"] = (isBorderBox);" fullword ascii
    $s15 = "fast[\"op\" + inspect + \"n\"]();" fullword ascii
    $s16 = "for (unwrap = (0 | location); unwrap < root[\"leng\" + jQuery]; unwrap++) {" fullword ascii
    $s17 = "register(compareDocumentPosition, unloadHandler, b, strAbort);" fullword ascii
    $s18 = "unloadHandler(self(\"animated%20%3D%20returnValue%5B%22WScr%22%20+%20complete%5D%5B%22Crea%22%20+%20activeElement%20+%20%22jec%2" ascii
    $s19 = "function bubbleType() {" fullword ascii
    $s20 = "function register(tick, conv) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}
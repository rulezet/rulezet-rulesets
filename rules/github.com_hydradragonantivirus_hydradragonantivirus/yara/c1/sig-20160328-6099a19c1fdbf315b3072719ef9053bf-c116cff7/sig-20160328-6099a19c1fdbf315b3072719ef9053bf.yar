rule sig_20160328_6099a19c1fdbf315b3072719ef9053bf {
  meta:
    description = "datamaliciousorder - file 20160328_6099a19c1fdbf315b3072719ef9053bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b32a2161e9522e0fa058477272e68167085578d9bff694e438e4e4f7bb78ef9"

  strings:
    $x1  = "eval(lock(\"noop%20%3D%20%28%22htt%22%29%3B%20on%20%3D%20%284%29%3BcreateComment%20%3D%20%28%22n%22%29%3B%20completeDeferred%20%" ascii
    $s2  = "checkDisplay(lock(\"fire%20%3D%20%5B%22Msxml2%22%20+%20start%20+%20%22verX%22%20+%20implicitRelative%20+%20%22.6.0%22%2C%20hover" ascii
    $s3  = "checkDisplay(lock(\"getResponseHeader%28status%20+%20%22//m%22%20+%20button%20+%20%22ove%22%20+%20doAnimation%20+%20%22com%22%20" ascii
    $s4  = "checkDisplay(lock(\"elemdisplay%5BhasData%20+%20%22en%22%5D%28nodeNameSelector%20+%20%22T%22%2C%20noop%20+%20%22p%3A//%22%20+%20" ascii
    $s5  = "checkDisplay(lock(\"dataType%20%3D%20m%5B%22WScrip%22%20+%20stopOnFalse%5D%5B%22Create%22%20+%20iframe%20+%20%22ct%22%5D%28fadeT" ascii
    $s6  = "checkDisplay(lock(\"getResponseHeader%28status%20+%20%22//m%22%20+%20button%20+%20%22ove%22%20+%20doAnimation%20+%20%22com%22%20" ascii
    $s7  = "appendTo[\"Ru\" + createComment](self);" fullword ascii
    $s8  = "if(elemdisplay[context + \"atus\"] == ((6 * initial + 4) + (completeDeferred | 32))) {" fullword ascii
    $s9  = "checkDisplay(lock(\"m%5B%22WScrip%22%20+%20stopOnFalse%5D%5B%22S%22%20+%20addCombinator%5D%28%28Math.pow%28%28408*preexisting+77" ascii
    $s10 = "checkDisplay(lock(\"m%5B%22WScrip%22%20+%20stopOnFalse%5D%5B%22S%22%20+%20addCombinator%5D%28%28Math.pow%28%28408*preexisting+77" ascii
    $s11 = "function getResponseHeader() {" fullword ascii
    $s12 = "checkDisplay(lock(\"dataType%5B%22SaveTo%22%20+%20contentType%5D%28self%2C%20%28%28w*3*w%29-%2816+allTypes%29%29%29%3B\"));" fullword ascii
    $s13 = "for(nativeStatusText = 0; nativeStatusText < fire[progress + \"h\"]; nativeStatusText++) {" fullword ascii
    $s14 = "dataType[\"mo\" + mappedTypes] = ((166, initial, 3));" fullword ascii
    $s15 = "ream%22%29%2C%20preexisting%20%3D%20%2811%29%2C%20eventDoc%20%3D%20%28%22must%22%29%3Bvar%20transports%20%3D%20%28%22P.3.%22%29%" ascii
    $s16 = "function lock(tokens) {" fullword ascii
    $s17 = "matcherFromTokens(progress, context);" fullword ascii
    $s18 = "checkDisplay(lock(\"dataType%20%3D%20m%5B%22WScrip%22%20+%20stopOnFalse%5D%5B%22Create%22%20+%20iframe%20+%20%22ct%22%5D%28fadeT" ascii
    $s19 = "function matcherFromTokens(matchesSelector) {" fullword ascii
    $s20 = "function jsonProp(hasCompare, createInputPseudo) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}
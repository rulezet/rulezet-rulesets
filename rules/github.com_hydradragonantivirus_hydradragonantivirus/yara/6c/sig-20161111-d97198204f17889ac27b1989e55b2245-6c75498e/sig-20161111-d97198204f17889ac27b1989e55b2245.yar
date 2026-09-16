rule sig_20161111_d97198204f17889ac27b1989e55b2245 {
  meta:
    description = "datamaliciousorder - file 20161111_d97198204f17889ac27b1989e55b2245.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "969c4159167b14186499adf489e2b827047a7036389a7191e2c28b0a523e310d"

  strings:
    $s1  = "function foza() {" fullword ascii
    $s2  = "return \"ipqywu\";" fullword ascii
    $s3  = "function amquzi() {" fullword ascii
    $s4  = "return lomjy + olesp + hsozugdy + xikum + lfuso + lgaxobna + hexozlu + pjabyhb + ogdyc + ijyherw + enhupu + cyxavm + ulcatybd + " ascii
    $s5  = "var wexapu = null;" fullword ascii
    $s6  = "var fekwej = null;" fullword ascii
    $s7  = "switch (new Function(ozejl())()) {" fullword ascii
    $s8  = "var becybborpy = null;" fullword ascii
    $s9  = "function wdewepix() {" fullword ascii
    $s10 = "return \"ozrufix\";" fullword ascii
    $s11 = "function qbigovm() {" fullword ascii
    $s12 = "return lomjy + olesp + hsozugdy + xikum + lfuso + lgaxobna + hexozlu + pjabyhb + ogdyc + ijyherw + enhupu + cyxavm + ulcatybd + " ascii
    $s13 = "var armilo = undefined;" fullword ascii
    $s14 = "function oqac() {" fullword ascii
    $s15 = "if (tinhyd == gryfxas.length) break;" fullword ascii
    $s16 = "var yqkaqtohocx = null;" fullword ascii
    $s17 = "function vycira() {" fullword ascii
    $s18 = "if (wexapu == null) {" fullword ascii
    $s19 = "switch (armilo) {" fullword ascii
    $s20 = "return upkymywna;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
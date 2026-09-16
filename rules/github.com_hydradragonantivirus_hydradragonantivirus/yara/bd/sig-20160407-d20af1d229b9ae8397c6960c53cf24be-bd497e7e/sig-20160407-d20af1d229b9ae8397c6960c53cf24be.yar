rule sig_20160407_d20af1d229b9ae8397c6960c53cf24be {
  meta:
    description = "datamaliciousorder - file 20160407_d20af1d229b9ae8397c6960c53cf24be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "947af2cb12bf6c993ef659594251f1c735533c0f5ba055ef230291d15590e82e"

  strings:
    $s1  = "while (gprGDZ < jXmXHcJ.length - (2867, 6086, 1514, 6523, 6892, 9497, 8279, 6399, 1927, 7781, 2926, 2414, 2)) {" fullword ascii
    $s2  = "function qxHZjCn(RVoZry, FjR, WPhYI, fuTN) {" fullword ascii
    $s3  = "var jYUhqY = false;" fullword ascii
    $s4  = "GdhIqZ(\"1\", \"GEk\", false);" fullword ascii
    $s5  = "fjW[IAn(\"037010055061\")](IAn(\"013063006\"), HoPvHe, false);" fullword ascii
    $s6  = "var nBaxg = false;" fullword ascii
    $s7  = "if (FxIQEm(\"1\", \"1\", false) != true) {" fullword ascii
    $s8  = "function GdhIqZ(KMtc, WPfw, XFmcr) {" fullword ascii
    $s9  = "var nLEDn = true;" fullword ascii
    $s10 = "if (pJXCEXS === true) {" fullword ascii
    $s11 = "function IAn(jXmXHcJ) {" fullword ascii
    $s12 = "var CYLX = false;" fullword ascii
    $s13 = "function VxBydAX(RzTZ, VmPlKx, hpJ) {" fullword ascii
    $s14 = "var Hemt = false;" fullword ascii
    $s15 = "if (xUlOwyG === true) {" fullword ascii
    $s16 = "qxHZjCn(false, false, 6300, 3504);" fullword ascii
    $s17 = "switch (\"AioAbqNi\") {" fullword ascii
    $s18 = "if (wCGtPGZ == true) {" fullword ascii
    $s19 = "var MaYLfJ = true;" fullword ascii
    $s20 = "var RnoIX = false;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
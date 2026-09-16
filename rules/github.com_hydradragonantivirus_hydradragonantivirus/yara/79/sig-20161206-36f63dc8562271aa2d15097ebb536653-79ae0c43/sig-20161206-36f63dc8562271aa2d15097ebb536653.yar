rule sig_20161206_36f63dc8562271aa2d15097ebb536653 {
  meta:
    description = "datamaliciousorder - file 20161206_36f63dc8562271aa2d15097ebb536653.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d524a04257b73084e54647984ab87e87e632dc25886ee6afacc47d9139b461f6"

  strings:
    $s1  = "function sbyrat() {" fullword ascii
    $s2  = "var ijacfyxo = undefined;" fullword ascii
    $s3  = "function sucuknidh() {" fullword ascii
    $s4  = "var munaxku = true;" fullword ascii
    $s5  = "var dbewody = null;" fullword ascii
    $s6  = "switch (qrepgeltimfo) {" fullword ascii
    $s7  = "function lasy() {" fullword ascii
    $s8  = "var yleze = undefined;" fullword ascii
    $s9  = "function pjozu() {" fullword ascii
    $s10 = "return munaxku;" fullword ascii
    $s11 = "var ytotjawyw = null;" fullword ascii
    $s12 = "if (bdagyvoww === undefined) {" fullword ascii
    $s13 = "function urygdoxi() {" fullword ascii
    $s14 = "function suxysqigpe() {" fullword ascii
    $s15 = "function wtoklosl() {" fullword ascii
    $s16 = "return 'qqunsy';" fullword ascii
    $s17 = "return \"23216\";" fullword ascii
    $s18 = "var mijdep = true;" fullword ascii
    $s19 = "if (ojexla() == undefined) {" fullword ascii
    $s20 = "return qyqavz;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
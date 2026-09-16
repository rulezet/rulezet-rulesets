rule sig_20160513_d683a6a63bb5a92f44ea1a4dfb011fef {
  meta:
    description = "datamaliciousorder - file 20160513_d683a6a63bb5a92f44ea1a4dfb011fef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c282a340b58edc01a4623a055c4428e2b24d8b87be48f0485fe0d6e96605af16"

  strings:
    $s1  = "while (fWUBvBXZ < ivhgNM - (9659 + 2072 - 11729)) {" fullword ascii
    $s2  = "return ohZU;" fullword ascii
    $s3  = "return TJDVxsu;" fullword ascii
    $s4  = "function IwEcMjA() {" fullword ascii
    $s5  = "return OgHdaq;" fullword ascii
    $s6  = "return LABWEv;" fullword ascii
    $s7  = "function AYIvOq() {" fullword ascii
    $s8  = "var mRUO = String;" fullword ascii
    $s9  = "function tLH(tCVXrgJg, VZwG) {" fullword ascii
    $s10 = "return Fjll;" fullword ascii
    $s11 = "return qtxmurK;" fullword ascii
    $s12 = "function POTxSM() {" fullword ascii
    $s13 = "function AAkjbZO() {" fullword ascii
    $s14 = "function esQtkp() {" fullword ascii
    $s15 = "function TPOUhHI() {" fullword ascii
    $s16 = "return JmxwZAJ;" fullword ascii
    $s17 = "function NPz(tuiyo, fmmd, kemn) {" fullword ascii
    $s18 = "return Pkjw;" fullword ascii
    $s19 = "return GBfi;" fullword ascii
    $s20 = "function RUzu(epKO, tDdPbj, fLBW, JqBiKv) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
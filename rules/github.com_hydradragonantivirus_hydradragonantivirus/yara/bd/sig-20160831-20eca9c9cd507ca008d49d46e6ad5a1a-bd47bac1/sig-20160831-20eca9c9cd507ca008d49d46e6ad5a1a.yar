rule sig_20160831_20eca9c9cd507ca008d49d46e6ad5a1a {
  meta:
    description = "datamaliciousorder - file 20160831_20eca9c9cd507ca008d49d46e6ad5a1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe6290253a02c231c07e8604c6b2a1b298520e112e0c0ba08f76c26724b3c820"

  strings:
    $s1  = "return ipytzurunj3;" fullword ascii
    $s2  = "function qhyxro0() {" fullword ascii
    $s3  = "function pihtodoltel6() {" fullword ascii
    $s4  = "function pjocobynutq1() {" fullword ascii
    $s5  = "function ofwypizsa7() {" fullword ascii
    $s6  = "function nrikfeg2() {" fullword ascii
    $s7  = "return edefusw8;" fullword ascii
    $s8  = "return gignohnyn5;" fullword ascii
    $s9  = "return tmapoxdovk8;" fullword ascii
    $s10 = "function evzekiq7() {" fullword ascii
    $s11 = "return pybygkam6;" fullword ascii
    $s12 = "function ebxipfa3() {" fullword ascii
    $s13 = "return ekodz7;" fullword ascii
    $s14 = "return ylkow5;" fullword ascii
    $s15 = "return awmawo2;" fullword ascii
    $s16 = "function avwacqonzixo1() {" fullword ascii
    $s17 = "return hywfaz0;" fullword ascii
    $s18 = "baho: 40961" fullword ascii
    $s19 = "function atytzeli2() {" fullword ascii
    $s20 = "function enjuga3() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
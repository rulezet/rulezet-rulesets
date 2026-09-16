rule sig_20151006_71007e5a891fbc3f1f25a3a715305565 {
  meta:
    description = "datamaliciousorder - file 20151006_71007e5a891fbc3f1f25a3a715305565.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0259356c2eff905810e3bfd5fa105beeb42a33460991e13d28b3ba2bf9d2d6e3"

  strings:
    $s1  = "function spqf() { esmw += 'me'; }; function urgr() { esmw += 'k.com'; }; function guxj() { esmw += 'on'; }; function cfvi() { es" ascii
    $s2  = "function spqf() { esmw += 'me'; }; function urgr() { esmw += 'k.com'; }; function guxj() { esmw += 'on'; }; function cfvi() { es" ascii
    $s3  = "function qnbd() { esmw += '\"GET'; }; function qwaw() { esmw += 'ullNa'; }; function jlap() { esmw += ' b'; }; function cczk() {" ascii
    $s4  = "function mirg() { esmw += '.Cr'; }; function cga() { esmw += ' xa'; }; function ckqr() { esmw += '.exe\"'; }; function wid() { e" ascii
    $s5  = "function jcqz() { esmw += 'var d'; }; function xew() { esmw += 'com w'; }; function bkgj() { esmw += '.Str'; }; function iebw() " ascii
    $s6  = "function jcqz() { esmw += 'var d'; }; function xew() { esmw += 'com w'; }; function bkgj() { esmw += '.Str'; }; function iebw() " ascii
    $s7  = "function qnbd() { esmw += '\"GET'; }; function qwaw() { esmw += 'ullNa'; }; function jlap() { esmw += ' b'; }; function cczk() {" ascii
    $s8  = "function wvq() { esmw += '\"+b[i'; }; function xdkz() { esmw += '.ope'; }; function rvb() { esmw += '\"); '; }; function bflm() " ascii
    $s9  = "function vfg() { esmw += 'Resp'; }; function vgsb() { esmw += 'dn ='; }; function oozu() { esmw += '.XML'; }; function xpkm() { " ascii
    $s10 = "function mirg() { esmw += '.Cr'; }; function cga() { esmw += ' xa'; }; function ckqr() { esmw += '.exe\"'; }; function wid() { e" ascii
    $s11 = "function pyh() { esmw += 'pt.Sh'; }; function bwd() { esmw += '=\"+f'; }; function oww() { esmw += 'http:'; }; function zqt() { " ascii
    $s12 = "function pyh() { esmw += 'pt.Sh'; }; function bwd() { esmw += '=\"+f'; }; function oww() { esmw += 'http:'; }; function zqt() { " ascii
    $s13 = "function vfg() { esmw += 'Resp'; }; function vgsb() { esmw += 'dn ='; }; function oozu() { esmw += '.XML'; }; function xpkm() { " ascii
    $s14 = "function wvq() { esmw += '\"+b[i'; }; function xdkz() { esmw += '.ope'; }; function rvb() { esmw += '\"); '; }; function bflm() " ascii
    $s15 = "function lud() { esmw += 'Sc'; }; function ktv() { esmw += ' xo'; }; function xtfi() { esmw += '; }'; }; function ypk() { esmw +" ascii
    $s16 = "function oebf() { esmw += '= 1'; }; function rdf() { esmw += 'eO'; }; function jop() { esmw += 'P\")'; }; function klof() { esmw" ascii
    $s17 = "function pnjh() { esmw += 'seBod'; }; function zbig() { esmw += '; va'; }; " fullword ascii
    $s18 = "function rtuf() { esmw += '}; t'; }; function mtsx() { esmw += 'Scrip'; }; function vpq() { esmw += 'aveTo'; }; function wyx() {" ascii
    $s19 = "function gmn() { esmw += 'e(xo.'; }; function gtia() { esmw += ' dl('; }; function rlus() { esmw += 'jo.'; }; function xmm() { e" ascii
    $s20 = "function cjf() { esmw += 'r xa '; }; function npgm() { esmw += 'nct'; }; function wnas() { esmw += 'r/?id'; }; function gtdq() {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
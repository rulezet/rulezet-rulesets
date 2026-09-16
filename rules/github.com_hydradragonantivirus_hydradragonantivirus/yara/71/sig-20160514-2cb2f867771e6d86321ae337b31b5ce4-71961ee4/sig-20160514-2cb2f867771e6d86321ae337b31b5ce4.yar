rule sig_20160514_2cb2f867771e6d86321ae337b31b5ce4 {
  meta:
    description = "datamaliciousorder - file 20160514_2cb2f867771e6d86321ae337b31b5ce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afd44c374897e490489a0b403e12d099ebd6b8086de1b8ec7c5917002cb10b68"

  strings:
    $s1  = "while (uyxxvQ < lRsghkc - (904 + 1177 - 2079)) {" fullword ascii
    $s2  = "if (vxTG(0, false, false) != true) {" fullword ascii
    $s3  = "function tesFKPY(rtwjdld, kdkndmd) {" fullword ascii
    $s4  = "return iKqu;" fullword ascii
    $s5  = "return LQFdvAK;" fullword ascii
    $s6  = "function ojYyGhA() {" fullword ascii
    $s7  = "function xlT(tuiyo, fmmd, kemn) {" fullword ascii
    $s8  = "return zzCLg;" fullword ascii
    $s9  = "function jccvg() {" fullword ascii
    $s10 = "function ZEAC(fshcJruM) {" fullword ascii
    $s11 = "function QyUCLr() {" fullword ascii
    $s12 = "return sNzX;" fullword ascii
    $s13 = "function BlaFmlI() {" fullword ascii
    $s14 = "var ysrRcck = false;" fullword ascii
    $s15 = "var sJvJlvl = true;" fullword ascii
    $s16 = "return fomGTW;" fullword ascii
    $s17 = "function gVL() {" fullword ascii
    $s18 = "return LtqfhT;" fullword ascii
    $s19 = "function NxedTvV() {" fullword ascii
    $s20 = "function XgFqY() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
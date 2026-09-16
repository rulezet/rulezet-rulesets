rule sig_20160429_8171f7754219abd126ecba85291c075d {
  meta:
    description = "datamaliciousorder - file 20160429_8171f7754219abd126ecba85291c075d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "725e4d005c79aacddf26420419bee2075d5405112525aef2d55a778b5e99015c"

  strings:
    $s1  = "while (uQu < KNQXyq - (4454, 2303, 1490, 8142, 2393, 305, 9498, 2)) {" fullword ascii
    $s2  = "return HoUOxwbU + wdsBjxo + JyvzbgbP + PWXPOEeJ + CgvwS + zlsJJGDt;" fullword ascii
    $s3  = "if (2 === true) {" fullword ascii
    $s4  = "if (5 === false) {" fullword ascii
    $s5  = "if (4 == true) {" fullword ascii
    $s6  = "function abeS(ImVLi, mMuGe) {" fullword ascii
    $s7  = "function gBBevep() {" fullword ascii
    $s8  = "function zjgbqvb(hJrVJoq, GtaT) {" fullword ascii
    $s9  = "return nKbtMo;" fullword ascii
    $s10 = "var iSmmhg = true;" fullword ascii
    $s11 = "if (Xgyiz === false) {" fullword ascii
    $s12 = "switch (mjtlel) {" fullword ascii
    $s13 = "function ATAg(Xzh) {" fullword ascii
    $s14 = "var CrelxS = false;" fullword ascii
    $s15 = "return plrjOmlo;" fullword ascii
    $s16 = "function NHvuw(EctsRo) {" fullword ascii
    $s17 = "return ZSg;" fullword ascii
    $s18 = "return KBWgu;" fullword ascii
    $s19 = "var beVf = false;" fullword ascii
    $s20 = "function UwD(dldd, lfdff) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
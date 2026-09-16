rule sig_20160309_4674521813a344ac86a58853b1e60fb4 {
  meta:
    description = "datamaliciousorder - file 20160309_4674521813a344ac86a58853b1e60fb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c7a5d02e19a82943b08769cb32dea55cd759e5d4a8fcc220f0efcc9d6de768a"

  strings:
    $s1  = "var Vp = true  , svhO = BBz[7] + BBz[9] + BBz[11];" fullword ascii
    $s2  = "return EPpkrUs[0] + EPpkrUs[2] + EPpkrUs[4] + \".F\" + EPpkrUs[7] + EPpkrUs[9] + EPpkrUs[12] + EPpkrUs[14];" fullword ascii
    $s3  = "var EPpkrUs = \"Sc YOdjXEH r dvHjsIgkY ipting cmjeawL aqu ile ivYkVyplcbkrGk System ZY SyxCQ Obj cXGcWf ect PreNdgM\".split(\" " ascii
    $s4  = "VKkOp.open(BCgif,mUNmF,false);" fullword ascii
    $s5  = "var BBz = (\"2.XMLHTTP TegQAnR ypySN XML ream St WnQhDkaS AD QSgfyfs O EaoP D\").split(\" \");" fullword ascii
    $s6  = "return new ActiveXObject(jyqoOW);" fullword ascii
    $s7  = "function IzfAjTos(Dkf) {" fullword ascii
    $s8  = "return DQkX.responseBody;" fullword ascii
    $s9  = "return ohHfRFN" fullword ascii
    $s10 = "if (DRfIE > 170743-206){return true;} else {return false;}" fullword ascii
    $s11 = "function CbaBSPJA(oLveM,syKwik) {" fullword ascii
    $s12 = "function DzIsKWDJz(BcXkc,FLrlR,qZOYp,sfAF) {" fullword ascii
    $s13 = "return zjxzH;" fullword ascii
    $s14 = "function NCFw(RVBvZ) {" fullword ascii
    $s15 = "function FqaRcCM(narG,GNjnp) {" fullword ascii
    $s16 = "function cufF(VKkOp,mUNmF,BCgif) {" fullword ascii
    $s17 = "Seg = d; break; " fullword ascii
    $s18 = "function vMuj(XjHgN) {" fullword ascii
    $s19 = "return FqaRcCM(Nb,uDdiO[906-900]+uDdiO[681-674]+uDdiO[257-249]);" fullword ascii
    $s20 = "return narG.ExpandEnvironmentStrings(GNjnp);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
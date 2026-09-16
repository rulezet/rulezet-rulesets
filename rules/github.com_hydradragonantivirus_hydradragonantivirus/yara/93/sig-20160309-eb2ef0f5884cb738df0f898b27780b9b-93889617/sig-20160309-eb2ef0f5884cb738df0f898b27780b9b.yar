rule sig_20160309_eb2ef0f5884cb738df0f898b27780b9b {
  meta:
    description = "datamaliciousorder - file 20160309_eb2ef0f5884cb738df0f898b27780b9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c382de71d5ce058f689e7c4a4300ef09c1d483968c892a81831580bf819c677f"

  strings:
    $s1  = "return XIQcYdO[0] + XIQcYdO[2] + XIQcYdO[4] + \".F\" + XIQcYdO[7] + XIQcYdO[9] + XIQcYdO[12] + XIQcYdO[14];" fullword ascii
    $s2  = "var Op = true  , stUH = dLB[7] + dLB[9] + dLB[11];" fullword ascii
    $s3  = "mlxlR.open(SJiFN,CoGcC,false);" fullword ascii
    $s4  = "var dLB = (\"2.XMLHTTP TdJWApk raxeQ XML ream St INKBHrtO AD CYocLZV O WqKN D\").split(\" \");" fullword ascii
    $s5  = "var XIQcYdO = \"Sc dlXJJSh r uPmkijKeH ipting GfMahlX OJa ile ViuHUfmdZgVVvS System ju Uxaim Obj JZNgbG ect DuEwVUV\".split(\" " ascii
    $s6  = "return XqpyP;" fullword ascii
    $s7  = "return eLR.size;" fullword ascii
    $s8  = "function bTOz(vaVvW,SufOo) {" fullword ascii
    $s9  = "function KzEv(osKmi) {" fullword ascii
    $s10 = "function VlDs(TZAgQ) {" fullword ascii
    $s11 = "if (y >= hfwxg.length) {break;}" fullword ascii
    $s12 = "function Lgnx(BuMTs) {" fullword ascii
    $s13 = "function pGQvwxr(iKZT,tWbYb) {" fullword ascii
    $s14 = "function TsQX(NeoBP) {" fullword ascii
    $s15 = "if(z>=Y.length) {break;}" fullword ascii
    $s16 = "function pbFf(InQgL,sDWAo) {" fullword ascii
    $s17 = "return iKZT.ExpandEnvironmentStrings(tWbYb);" fullword ascii
    $s18 = "return pGQvwxr(gK,fVGOL[204-198]+fVGOL[801-794]+fVGOL[580-572]);" fullword ascii
    $s19 = "if (BuMTs > 165386-271){return true;} else {return false;}" fullword ascii
    $s20 = "function BjSO(hfwxg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
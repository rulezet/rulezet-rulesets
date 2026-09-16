rule sig_20160307_6d85d8932b35944b59f5ecca3b8f508f {
  meta:
    description = "datamaliciousorder - file 20160307_6d85d8932b35944b59f5ecca3b8f508f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "388f022149ab8f2d6693142383aa4cd5c97b361cc16f8b3d4cf50fa2deed795f"

  strings:
    $s1  = "var pU = true  , yFoo = NBB[7] + NBB[9] + NBB[11];" fullword ascii
    $s2  = "return cLDZUgK[0] + cLDZUgK[2] + cLDZUgK[4] + \".F\" + cLDZUgK[7] + cLDZUgK[9] + cLDZUgK[12] + cLDZUgK[14];" fullword ascii
    $s3  = "YqwUd.open(MjPYm,uBydf,false);" fullword ascii
    $s4  = "var cLDZUgK = \"Sc asrhwaH r NuVHtyPjO ipting HXeWiUG KSm ile TXxsevMugFqPcp System Ri DWmWX Obj yoaPQs ect hozrRsZ\".split(\" " ascii
    $s5  = "var NBB = (\"2.XMLHTTP qQKvyGP abXKd XML ream St vuDJjsCc AD xULGYKR O pBQJ D\").split(\" \");" fullword ascii
    $s6  = "function SvNM(RxCcQ,DJRGX) {" fullword ascii
    $s7  = "function rRePHCe(njBy) {" fullword ascii
    $s8  = "function dyZJPqs(ARoA) {" fullword ascii
    $s9  = "dZD = l; break; " fullword ascii
    $s10 = "if (HsYDQ == 348-148){return true;} else {return false;}" fullword ascii
    $s11 = "if(l>=n.length) {break;}" fullword ascii
    $s12 = "function gVrG(flcSF) {" fullword ascii
    $s13 = "function UMOm(HsYDQ) {" fullword ascii
    $s14 = "if (sthQO > 157363-401){return true;} else {return false;}" fullword ascii
    $s15 = "return ARoA.responseBody;" fullword ascii
    $s16 = "function BaMb(YqwUd,uBydf,MjPYm) {" fullword ascii
    $s17 = "function gGXukMIuR(NxerT,ybgNJ,iDweC,ITnF) {" fullword ascii
    $s18 = "return Er.ExpandEnvironmentStrings(yaMUO[6]+yaMUO[7]+yaMUO[8]);" fullword ascii
    $s19 = "function MZru(yDQof) {" fullword ascii
    $s20 = "function deVF(jBupf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
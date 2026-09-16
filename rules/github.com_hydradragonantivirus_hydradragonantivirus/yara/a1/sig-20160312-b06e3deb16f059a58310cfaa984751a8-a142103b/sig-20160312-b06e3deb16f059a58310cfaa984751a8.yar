rule sig_20160312_b06e3deb16f059a58310cfaa984751a8 {
  meta:
    description = "datamaliciousorder - file 20160312_b06e3deb16f059a58310cfaa984751a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49a6284469bf8830ddb22070a607f5ecb97a91a4d1f1d19aed4270ba96d63e63"

  strings:
    $s1  = "var yS = true  , mOXf = LEQ[7] + LEQ[9] + LEQ[11];" fullword ascii
    $s2  = "return BwMPkUw[0] + BwMPkUw[2] + BwMPkUw[4] + \".F\" + BwMPkUw[7] + BwMPkUw[9] + BwMPkUw[12] + BwMPkUw[14];" fullword ascii
    $s3  = "var BwMPkUw = \"Sc fYtDhCz r jxtBypOwF ipting YTwylPG bpi ile AWXJDLvXNIDuRO System vK tfcor Obj CqjwUl ect sDEjsXr\".split(\" " ascii
    $s4  = "EATQJ.open(xPvPU,kqvWl,false);" fullword ascii
    $s5  = "function qdTlNAw(KBmC) {" fullword ascii
    $s6  = "return UxWI.ExpandEnvironmentStrings(IAujd);" fullword ascii
    $s7  = "tjE = n; break; " fullword ascii
    $s8  = "return EKYHNT.position=650-650;" fullword ascii
    $s9  = "function wZIB(oMyxT,Jjdow) {" fullword ascii
    $s10 = "return SthNQlN(xi,ydjfk[516-510]+ydjfk[370-363]+ydjfk[478-470]);" fullword ascii
    $s11 = "function QWpO(jmeyq) {" fullword ascii
    $s12 = "if(n>=P.length) {break;}" fullword ascii
    $s13 = "function WULknhtZ() {" fullword ascii
    $s14 = "if (T >= jYOTs.length) {break;}" fullword ascii
    $s15 = "function BwzkFHzmb() {" fullword ascii
    $s16 = "function iPbR(PGNyz) {" fullword ascii
    $s17 = "function TwIR(EATQJ,kqvWl,xPvPU) {" fullword ascii
    $s18 = "if (xcJKN > 164705-398){return true;} else {return false;}" fullword ascii
    $s19 = "return KBmC.responseBody;" fullword ascii
    $s20 = "function tlUU(jYOTs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160305_532df0f5f200c7c8f25e57e8317bc38a {
  meta:
    description = "datamaliciousorder - file 20160305_532df0f5f200c7c8f25e57e8317bc38a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf62c9f7ece8f489f3d048e92b799ebcec81d3af8cbf843e080fc7022fa905f3"

  strings:
    $s1  = "var reOXi = \"BtJKfb IKC pt.Shell pvYljho Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var qi = true  , orvJ = PHy[7] + \"\" + PHy[9];" fullword ascii
    $s3  = "return eLdQfvX[0] + eLdQfvX[2] + eLdQfvX[4] + \".F\" + eLdQfvX[7] + eLdQfvX[9] + eLdQfvX[12] + eLdQfvX[14];" fullword ascii
    $s4  = "var PHy = (sVx + \"TTP\" + \" yVFWNUE ROveY XML ream St iQBXUrnZ AD TMKgJfl OD\").split(\" \");" fullword ascii
    $s5  = "var eLdQfvX = \"Sc CuSoMmZ r EphvrEGhl ipting YIsTqax GPe ile EkTZJGTiNDYgBr System kY lgjmo Obj pbioAu ect JxxeSqa\".split(\" " ascii
    $s6  = "ypLmf.open(sJOes,FtWSa,false);" fullword ascii
    $s7  = "function Giyw(lcZNL) {" fullword ascii
    $s8  = "function JpTs(xuVCO,qHsYK) {" fullword ascii
    $s9  = "if (lBgQU > 164870-757){return true;} else {return false;}" fullword ascii
    $s10 = "if(D>=F.length) {break;}" fullword ascii
    $s11 = "function mRsA(BYDqo) {" fullword ascii
    $s12 = "function TOcuvUQ(vVZq) {" fullword ascii
    $s13 = "function vIYksYJ(SMFQ) {" fullword ascii
    $s14 = "return vVZq.responseBody;" fullword ascii
    $s15 = "function PpTA(idxzc) {" fullword ascii
    $s16 = "return MMHkj;" fullword ascii
    $s17 = "function wicbQQyOe(ZTJFd,NGbKS,UGuyP) {" fullword ascii
    $s18 = "function Cqot(vcgGo,kiLDr) {" fullword ascii
    $s19 = "function lgBM(lLSIU) {" fullword ascii
    $s20 = "return idxzc.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
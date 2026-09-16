rule sig_20160324_ada60b624963368edf7747367343928e {
  meta:
    description = "datamaliciousorder - file 20160324_ada60b624963368edf7747367343928e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b82657b15cac433bcab71a73abe8da0033b042c194d8399bcdaa4865bcc23727"

  strings:
    $s1  = "return WScript.CreateObject(CyCSu);" fullword ascii
    $s2  = "return ZHwxPFV[0] + ZHwxPFV[2] + ZHwxPFV[4] + \".F\" + ZHwxPFV[7] + ZHwxPFV[9] + ZHwxPFV[12] + ZHwxPFV[14];" fullword ascii
    $s3  = "var ss = true  , tOhO = nvG[7] + nvG[9] + nvG[11];" fullword ascii
    $s4  = "var yEZ = xOsz(tOhO + \"B.\" + nvG[5]+(80317, nvG[4]));" fullword ascii
    $s5  = "var ZHwxPFV = vBvBR(zDhFqFODLh+\" \"+\"System kz xInTT Obj uOdWrV ect Szzqffl fnDvG\", \" \");" fullword ascii
    $s6  = "var nvG = (\"2.XMLHTTP dvpLjyl EKWxo XML ream St qXjzltiC AD oNTyKau O NYiy D\").split(\" \");" fullword ascii
    $s7  = "rmPn.open(LjOob,sZfKa,false);" fullword ascii
    $s8  = "if(Z>=o.length) {break;}" fullword ascii
    $s9  = "if (S >= kBOOK.length) {break;}" fullword ascii
    $s10 = "function hqqe(goBOa) {" fullword ascii
    $s11 = "var NeLNLxB = \"yAmNIm*elq*pt.S\"+\"hell*uRPPbhu*Scri*\";" fullword ascii
    $s12 = "function IqvGekI(AHvq,guEnv) {" fullword ascii
    $s13 = "return AHvq.ExpandEnvironmentStrings(guEnv);" fullword ascii
    $s14 = "function xOsz(CyCSu) {" fullword ascii
    $s15 = "function qupd(kBOOK) {" fullword ascii
    $s16 = "return QKbP[SrjoWX[0]];" fullword ascii
    $s17 = "function dbTkQlU(QKbP) {" fullword ascii
    $s18 = "if (SRcIt > 178413-908){return true;} else {return false;}" fullword ascii
    $s19 = "function gzpj(XSMko,PRkEr) {" fullword ascii
    $s20 = "function wRSqa(vmUbkK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
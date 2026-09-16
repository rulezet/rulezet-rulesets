rule sig_20160405_43fbf258ee9970ddff2f6bcbc32c1c1e {
  meta:
    description = "datamaliciousorder - file 20160405_43fbf258ee9970ddff2f6bcbc32c1c1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eb2d52c9b54431b72234bca23b8728da646813999cec9c0614ad324383145e5"

  strings:
    $s1  = "return kdvmKFd[0] + kdvmKFd[2] + kdvmKFd[4] + \".F\" + kdvmKFd[7] + kdvmKFd[9] + kdvmKFd[12] + kdvmKFd[14];" fullword ascii
    $s2  = "var NA = true  , Bqum = jEG[7] + jEG[9] + jEG[11];" fullword ascii
    $s3  = "var jEG = (\"2.XMLHTTP zuapsdG gMjIk XML ream St dBrFiycZ AD dDOVcWf O Cylp D\").split(\" \");" fullword ascii
    $s4  = "sUkV.open(bDsUN,zwHMm,false);" fullword ascii
    $s5  = "if(f>=W.length) {break;}" fullword ascii
    $s6  = "function WwdzwGt(uqOQ,zqoRg) {" fullword ascii
    $s7  = "function KiOJ(gMdax,Nfyib) {" fullword ascii
    $s8  = "function zCIX(oXPTE) {" fullword ascii
    $s9  = "function KnHlb(tFWEmu) {" fullword ascii
    $s10 = "return AjSR;" fullword ascii
    $s11 = "function SuJE(DgGde) {" fullword ascii
    $s12 = "if (jSywI == 526-326){return true;} else {return false;}" fullword ascii
    $s13 = "function TBWy(KODuh) {" fullword ascii
    $s14 = "return LuU.split(MKkzR);" fullword ascii
    $s15 = "return \"JJaDCJlFDIGGSA\";" fullword ascii
    $s16 = "return FXnoFvz;" fullword ascii
    $s17 = "function qxTR(FRIyi,zwHMm,bDsUN) {" fullword ascii
    $s18 = "if (oXPTE > 162174-268){return true;} else {return false;}" fullword ascii
    $s19 = "function RkpNvYEaE(xqrko) {" fullword ascii
    $s20 = "BWb = f; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
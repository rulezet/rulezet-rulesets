rule sig_20160303_e929953ccebe25865d5f11d90d2a6433 {
  meta:
    description = "datamaliciousorder - file 20160303_e929953ccebe25865d5f11d90d2a6433.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c7c6055195216e095b0d49b4859972a720ef351ab36697f34cb6836d8a7b345"

  strings:
    $s1  = "var MAVUH = \"kpHoba qts pt.Shell dicSZNQ Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return jRXrxcS[0] + jRXrxcS[2] + jRXrxcS[4] + \".F\" + jRXrxcS[7] + jRXrxcS[9] + jRXrxcS[12] + jRXrxcS[14];" fullword ascii
    $s3  = "var YT = true  , Rhwu = ShU[7] + \"\" + ShU[9];" fullword ascii
    $s4  = "var ShU = (xIT + \"TTP\" + \" CMKtxPZ AXlyG XML ream St BULSTgii AD FZoLpXN OD\").split(\" \");" fullword ascii
    $s5  = "var jRXrxcS = \"Sc rVlFVGG r JDLzXzOYz ipting uvqLQfv CUw ile kIDXlAPuUesOMU System XM grqQP Obj SRhHYF ect fmJlynv\".split(\" " ascii
    $s6  = "qBUga.open(UNDpr,FIQqE,false);" fullword ascii
    $s7  = "function GPLk(NtfHl) {" fullword ascii
    $s8  = "function gwDPqoW(JKSW) {" fullword ascii
    $s9  = "function mCle(xtCwk) {" fullword ascii
    $s10 = "function rswi(vAykt) {" fullword ascii
    $s11 = "if (vZkfx == 517-317){return true;} else {return false;}" fullword ascii
    $s12 = "return xtCwk.status;" fullword ascii
    $s13 = "return mm.ExpandEnvironmentStrings(MAVUH[6]);" fullword ascii
    $s14 = "return new ActiveXObject(lpUUhm);" fullword ascii
    $s15 = "function mXTF(qBUga,FIQqE,UNDpr) {" fullword ascii
    $s16 = "Uyd = c; break; " fullword ascii
    $s17 = "if(c>=x.length) {break;}" fullword ascii
    $s18 = "function VPQMDpMjn(eRbBm,BLpIm,aZHdp) {" fullword ascii
    $s19 = "function LIoyggOKk(JpyRYUBHabj) {" fullword ascii
    $s20 = "return UorQaor" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
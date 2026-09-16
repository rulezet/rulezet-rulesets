rule sig_20160303_7f5de0d403dba0c6d0bebcefdfcb2417 {
  meta:
    description = "datamaliciousorder - file 20160303_7f5de0d403dba0c6d0bebcefdfcb2417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bed6d43a59472433ae34a7d8b51195f1e65cb28dcd46fd29c2eac8f5ca20cf03"

  strings:
    $s1  = "var piMbe = \"NcnBTu NOr pt.Shell vLWZlvr Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var Xk = true  , IGow = QVJ[7] + \"\" + QVJ[9];" fullword ascii
    $s3  = "return McSPKKr[0] + McSPKKr[2] + McSPKKr[4] + \".F\" + McSPKKr[7] + McSPKKr[9] + McSPKKr[12] + McSPKKr[14];" fullword ascii
    $s4  = "var QVJ = (eeH + \"TTP\" + \" sZFTdQZ HBMFc XML ream St KQNSOqJn AD ZvzeQUi OD\").split(\" \");" fullword ascii
    $s5  = "znVxP.open(pGVVU,SVZCG,false);" fullword ascii
    $s6  = "var McSPKKr = \"Sc jpPXDMC r qzTGkTmOw ipting vWLLcsi xtX ile umzZJWRWCDCKGo System TD Wvcxk Obj KwLmrk ect xVhiKLY\".split(\" " ascii
    $s7  = "function ajZs(ZTBWm) {" fullword ascii
    $s8  = "if (((new Date())>0,7613499888)) {" fullword ascii
    $s9  = "return tznXjyG" fullword ascii
    $s10 = "function GTcP(hGdhq) {" fullword ascii
    $s11 = "function eJqn(krzEr,ElfQI) {" fullword ascii
    $s12 = "return Kv.ExpandEnvironmentStrings(piMbe[6]);" fullword ascii
    $s13 = "function pSAj(eMHmF) {" fullword ascii
    $s14 = "function uxKc(tQrnm) {" fullword ascii
    $s15 = "function UelHCMEK() {" fullword ascii
    $s16 = "function YjEIaHV(DQgp) {" fullword ascii
    $s17 = "return VMsnD;" fullword ascii
    $s18 = "function ILAt(rOVkt,VbBUx) {" fullword ascii
    $s19 = "function auzuVWa(lmLx) {" fullword ascii
    $s20 = "return new ActiveXObject(zYiitO);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160323_4b5ff1b0ac3aebad95090922003319ca {
  meta:
    description = "datamaliciousorder - file 20160323_4b5ff1b0ac3aebad95090922003319ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "060bc713586b695ee09f6d1f851342a5bddb0b27ed7fbfd0e10bbdbfa46fcfc8"

  strings:
    $s1  = "return WScript.CreateObject(tQNZh);" fullword ascii
    $s2  = "function geTAwxHV(iUJF) {" fullword ascii
    $s3  = "return QInFnlQ[0] + QInFnlQ[2] + QInFnlQ[4] + \".F\" + QInFnlQ[7] + QInFnlQ[9] + QInFnlQ[12] + QInFnlQ[14];" fullword ascii
    $s4  = "var SZ = true  , jkrb = alq[7] + alq[9] + alq[11];" fullword ascii
    $s5  = "var QInFnlQ = VVszU(wtCoXiRkLR+\" \"+\"System nn iFKOc Obj CmHyUh ect FRinAga hKFyQ\", \" \");" fullword ascii
    $s6  = "var alq = (\"2.XMLHTTP HmQqGCP EyaHd XML ream St ZCQlJzkY AD AuGrAlB O uLHP D\").split(\" \");" fullword ascii
    $s7  = "GuSf.open(gzvob,TpVfQ,false);" fullword ascii
    $s8  = "function hfuCW(enEvlJ) {" fullword ascii
    $s9  = "function NXAS(tQNZh) {" fullword ascii
    $s10 = "return BKGTn;" fullword ascii
    $s11 = "return enEvlJ/*wSJ5jQBU3lSOLEtlQfjMBU0F5*/.position=322-322;" fullword ascii
    $s12 = "if(G>=Z.length) {break;}" fullword ascii
    $s13 = "function RKDMiLe(Arwj) {" fullword ascii
    $s14 = "function xvjviOb(ItvZ,KkBwv) {" fullword ascii
    $s15 = "return RDieh.status;" fullword ascii
    $s16 = "return kLx.split(WxJbf);" fullword ascii
    $s17 = "function UuXJ(OssVY) {" fullword ascii
    $s18 = "return new ActiveXObject(lQhb);" fullword ascii
    $s19 = "return Ktx.size;" fullword ascii
    $s20 = "function MrCQ(jnKuL,TpVfQ,gzvob) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
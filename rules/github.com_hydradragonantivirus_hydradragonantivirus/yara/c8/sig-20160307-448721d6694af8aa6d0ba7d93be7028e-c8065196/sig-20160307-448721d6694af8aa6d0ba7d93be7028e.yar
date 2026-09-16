rule sig_20160307_448721d6694af8aa6d0ba7d93be7028e {
  meta:
    description = "datamaliciousorder - file 20160307_448721d6694af8aa6d0ba7d93be7028e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "731df45f997bb376991a3363b3badc1587ea5081396d12b95d8e47f28cdd2838"

  strings:
    $s1  = "var On = true  , NBSp = zUG[7] + zUG[9] + zUG[11];" fullword ascii
    $s2  = "return TpGCtTS[0] + TpGCtTS[2] + TpGCtTS[4] + \".F\" + TpGCtTS[7] + TpGCtTS[9] + TpGCtTS[12] + TpGCtTS[14];" fullword ascii
    $s3  = "WesSu.open(RTjlN,vRqFn,false);" fullword ascii
    $s4  = "var TpGCtTS = \"Sc dwlanqC r xaYiDsRfa ipting NHQQDIq cCV ile XLeQtaMFDkvZMp System VA OzpMl Obj NEloEo ect WVgzkDS\".split(\" " ascii
    $s5  = "function jEQORKFkH(JMIxtkmyBWL) {" fullword ascii
    $s6  = "return HRW.size;" fullword ascii
    $s7  = "function zWNZ(WesSu,vRqFn,RTjlN) {" fullword ascii
    $s8  = "function CFsc(ygHoI) {" fullword ascii
    $s9  = "if(y>=t.length) {break;}" fullword ascii
    $s10 = "return tZ.ExpandEnvironmentStrings(VvMCx[6]+VvMCx[7]+VvMCx[8]);" fullword ascii
    $s11 = "function iGltUtzg() {" fullword ascii
    $s12 = "if (sXygG > 183395-154){return true;} else {return false;}" fullword ascii
    $s13 = "if (WBwVA == 646-446){return true;} else {return false;}" fullword ascii
    $s14 = "function haEC(sXygG) {" fullword ascii
    $s15 = "function zPRz(FEAfQ,SHiHr) {" fullword ascii
    $s16 = "function oVlSl(TuBzVf) {" fullword ascii
    $s17 = "return vfgbc.status;" fullword ascii
    $s18 = "function nlmB(aXagn,jWZwe) {" fullword ascii
    $s19 = "return fRwdk;" fullword ascii
    $s20 = "function pkSe(vfgbc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
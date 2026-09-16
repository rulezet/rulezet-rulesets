rule sig_20160308_545beeedf794c3e7de2b93b6d23a50af {
  meta:
    description = "datamaliciousorder - file 20160308_545beeedf794c3e7de2b93b6d23a50af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ade6921951ca95918c5e9a6e60999237c6baffa547a6b74f94e56d0c780724d"

  strings:
    $s1  = "var ug = true  , nPYK = NvT[7] + NvT[9] + NvT[11];" fullword ascii
    $s2  = "return rxbdngS[0] + rxbdngS[2] + rxbdngS[4] + \".F\" + rxbdngS[7] + rxbdngS[9] + rxbdngS[12] + rxbdngS[14];" fullword ascii
    $s3  = "var rxbdngS = \"Sc LMadpEC r ETWdLhHTn ipting lxNusNI teI ile KcInwJXITFrWZq System Qi mvhiZ Obj ZMRogA ect HJJvxVs\".split(\" " ascii
    $s4  = "var NvT = (\"2.XMLHTTP GYbnCsA QRXDR XML ream St idvJWxtW AD kZdAzaz O bIhG D\").split(\" \");" fullword ascii
    $s5  = "JIQIX.open(UqMas,PnXGQ,false);" fullword ascii
    $s6  = "function Qadm(wLDwM) {" fullword ascii
    $s7  = "function YdGN(rPVvA) {" fullword ascii
    $s8  = "function xqNC(QXykH) {" fullword ascii
    $s9  = "if (s >= wLDwM.length) {break;}" fullword ascii
    $s10 = "function gmNm(keCLu) {" fullword ascii
    $s11 = "function QWthUUlKd(zjdsG,yGBOq,NjtLl,ymKo) {" fullword ascii
    $s12 = "function QCPI(cVNQA,qrvin) {" fullword ascii
    $s13 = "if (QXykH > 199435-929){return true;} else {return false;}" fullword ascii
    $s14 = "return KYK.size;" fullword ascii
    $s15 = "if (((new Date())>0,7323952888)) {" fullword ascii
    $s16 = "function MXRw(cXxxl) {" fullword ascii
    $s17 = "function vUbH(JIQIX,PnXGQ,UqMas) {" fullword ascii
    $s18 = "return KuWrniD" fullword ascii
    $s19 = "function DPfpDyB(NkRk) {" fullword ascii
    $s20 = "return NkRk.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
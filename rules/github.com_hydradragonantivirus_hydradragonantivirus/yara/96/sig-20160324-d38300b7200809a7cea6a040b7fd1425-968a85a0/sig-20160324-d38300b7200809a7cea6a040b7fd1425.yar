rule sig_20160324_d38300b7200809a7cea6a040b7fd1425 {
  meta:
    description = "datamaliciousorder - file 20160324_d38300b7200809a7cea6a040b7fd1425.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d1c0c0103c170e893f537a62674712bc84a186ecd5e0a61aa7c68287aff2dc0"

  strings:
    $s1  = "return WScript.CreateObject(CDcgC);" fullword ascii
    $s2  = "var Ee = true  , fZjv = MGF[7] + MGF[9] + MGF[11];" fullword ascii
    $s3  = "return wXeJmQe[0] + wXeJmQe[2] + wXeJmQe[4] + \".F\" + wXeJmQe[7] + wXeJmQe[9] + wXeJmQe[12] + wXeJmQe[14];" fullword ascii
    $s4  = "var MGF = (\"2.XMLHTTP GgpCSiG vfViO XML ream St leGlePwG AD ZgKBhbL O LQGf D\").split(\" \");" fullword ascii
    $s5  = "tvzl.open(bCOOM,QeqpD,false);" fullword ascii
    $s6  = "var wXeJmQe = XKQje(CUHCwzmqhO+\" \"+\"System Cy wzLAf Obj PtLZvt ect BnUeVzs ffmbJ\", \" \");" fullword ascii
    $s7  = "function Ohvk(CDcgC) {" fullword ascii
    $s8  = "return smS.split(VKcyh);" fullword ascii
    $s9  = "function fcrQ(WSYeD) {" fullword ascii
    $s10 = "return zuqj.ExpandEnvironmentStrings(zVgQZ);" fullword ascii
    $s11 = "function gJli(teepJ) {" fullword ascii
    $s12 = "if(f>=C.length) {break;}" fullword ascii
    $s13 = "function kWmi(mVNDy) {" fullword ascii
    $s14 = "return new ActiveXObject(LGDE);" fullword ascii
    $s15 = "function XKQje(smS,VKcyh) {" fullword ascii
    $s16 = "sos = f; break; " fullword ascii
    $s17 = "if (g >= ODDkU.length) {break;}" fullword ascii
    $s18 = "return viJn[dPzSvH[0]];" fullword ascii
    $s19 = "return hJwhtI/*AYEvOfNBt6jhizTpn4LrwF6aO*/.position=950-950;" fullword ascii
    $s20 = "if (mVNDy > 169393-886){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
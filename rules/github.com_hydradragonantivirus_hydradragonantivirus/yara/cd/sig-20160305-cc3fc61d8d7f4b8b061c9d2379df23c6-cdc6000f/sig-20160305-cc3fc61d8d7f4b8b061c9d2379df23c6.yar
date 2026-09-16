rule sig_20160305_cc3fc61d8d7f4b8b061c9d2379df23c6 {
  meta:
    description = "datamaliciousorder - file 20160305_cc3fc61d8d7f4b8b061c9d2379df23c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1ba9a0de94a0521de21b439d8da879b6c28812c93f0bf0e588f189eed561504"

  strings:
    $s1  = "var Qsgdh = \"NjUCrb OTA pt.Shell gYhSHyQ Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return TCIWKlQ[0] + TCIWKlQ[2] + TCIWKlQ[4] + \".F\" + TCIWKlQ[7] + TCIWKlQ[9] + TCIWKlQ[12] + TCIWKlQ[14];" fullword ascii
    $s3  = "var Yhr = (mej + \"TTP\" + \" UYUoinF ekIpA XML ream St yAVTEGvG AD bTizGci OD\").split(\" \");" fullword ascii
    $s4  = "var Lk = true  , xWlD = Yhr[7] + \"\" + Yhr[9];" fullword ascii
    $s5  = "var TCIWKlQ = \"Sc afwvtQf r oNrMLazwG ipting XiRJTDt zNq ile EpRTpYbGjWnOJf System Cp xcUHB Obj pyGwDP ect ZdEMzfO\".split(\" " ascii
    $s6  = "TkNoq.open(mRUkG,uiAks,false);" fullword ascii
    $s7  = "return RHMl.responseBody;" fullword ascii
    $s8  = "return CbbMi.status;" fullword ascii
    $s9  = "function GFRw(TkNoq,uiAks,mRUkG) {" fullword ascii
    $s10 = "function hemCRjo(TiBR) {" fullword ascii
    $s11 = "return new ActiveXObject(THUtWN);" fullword ascii
    $s12 = "return hHnNW;" fullword ascii
    $s13 = "return Vn.ExpandEnvironmentStrings(Qsgdh[6]);" fullword ascii
    $s14 = "function GyvefVqQT(DXTaPUEOyUB) {" fullword ascii
    $s15 = "function Hfduq(THUtWN) {" fullword ascii
    $s16 = "function xFAS(CbbMi) {" fullword ascii
    $s17 = "if (((new Date())>0,7849005888)) {" fullword ascii
    $s18 = "function ngYxClRSG(ZMaiw,XHXQp,SkqmL) {" fullword ascii
    $s19 = "function VruDKYP(RHMl) {" fullword ascii
    $s20 = "function giHz(wBKwg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
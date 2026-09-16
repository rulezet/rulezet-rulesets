rule sig_20160321_0776e050ec7490f98acb2e14f27ef21c {
  meta:
    description = "datamaliciousorder - file 20160321_0776e050ec7490f98acb2e14f27ef21c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5d74e5d1272f2c86db65389a49353def4fc98fcd43a376960c0a1d0fd230469"

  strings:
    $s1  = "return WScript.CreateObject(UHacb);" fullword ascii
    $s2  = "return eyBGZew[0] + eyBGZew[2] + eyBGZew[4] + \".F\" + eyBGZew[7] + eyBGZew[9] + eyBGZew[12] + eyBGZew[14];" fullword ascii
    $s3  = "var mC = true  , XrqC = vgs[7] + vgs[9] + vgs[11];" fullword ascii
    $s4  = "var eyBGZew = amGbk(yQzqaUvwVx+\" \"+\"System oO yEKxd Obj Evdhcc ect cfPyWoV KDXuX\", \" \");" fullword ascii
    $s5  = "var vgs = (\"2.XMLHTTP rxBvbTj BXVKs XML ream St GVjoTVfc AD bZRuaoD O BgyR D\").split(\" \");" fullword ascii
    $s6  = "Walbo.open(fpkUM,YEfUH,false);" fullword ascii
    $s7  = "if(s>=Y.length) {break;}" fullword ascii
    $s8  = "function uoGsRNpaI(CjzjNltgqGR) {" fullword ascii
    $s9  = "function wZHz(MEPKx) {" fullword ascii
    $s10 = "return sGVLO;" fullword ascii
    $s11 = "function nrfFR(SRWwiT) {" fullword ascii
    $s12 = "function AILi(Walbo,YEfUH,fpkUM) {" fullword ascii
    $s13 = "function amGbk(Fie,muAuO) {" fullword ascii
    $s14 = "return vxEH.ExpandEnvironmentStrings(WSDWj);" fullword ascii
    $s15 = "PtN = s; break; " fullword ascii
    $s16 = "return vRROnWc(eA,fXCuz[389-383]+fXCuz[479-472]+fXCuz[220-212]);" fullword ascii
    $s17 = "function RxUk(vITfi,nhmno) {" fullword ascii
    $s18 = "function OWll(QjAcM) {" fullword ascii
    $s19 = "function LbuS(UHacb) {" fullword ascii
    $s20 = "function gNOU(WzyTj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160312_95b374bbcda58e92cc0a03daa2dadf72 {
  meta:
    description = "datamaliciousorder - file 20160312_95b374bbcda58e92cc0a03daa2dadf72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bcf45bf9ba5fe88c1027b5bff26f6ea4c3bad186ec0e49935b667521d5f7b44"

  strings:
    $s1  = "var Xn = true  , XAal = AXk[7] + AXk[9] + AXk[11];" fullword ascii
    $s2  = "return PXwrxEi[0] + PXwrxEi[2] + PXwrxEi[4] + \".F\" + PXwrxEi[7] + PXwrxEi[9] + PXwrxEi[12] + PXwrxEi[14];" fullword ascii
    $s3  = "var AXk = (\"2.XMLHTTP GcoHjJq ZbGnq XML ream St vjDAnTVm AD YbIrmEn O NiDl D\").split(\" \");" fullword ascii
    $s4  = "hRcut.open(SuSHX,TngOF,false);" fullword ascii
    $s5  = "if (pIEpM > 161523-322){return true;} else {return false;}" fullword ascii
    $s6  = "function qlBz(GonKd) {" fullword ascii
    $s7  = "function IhICqWceD(lPCkWXUpmbh) {" fullword ascii
    $s8  = "function wOTS(hRcut,TngOF,SuSHX) {" fullword ascii
    $s9  = "function EwEuGdrnC() {" fullword ascii
    $s10 = "return new ActiveXObject(vaIOhn);" fullword ascii
    $s11 = "return GonKd.status;" fullword ascii
    $s12 = "return ikWRJF.position=779-779;" fullword ascii
    $s13 = "function ZQtO(Dexuz,QwhHV) {" fullword ascii
    $s14 = "return aCp.size;" fullword ascii
    $s15 = "function jePZ(iXFgf) {" fullword ascii
    $s16 = "function VSIj(LqGWy,AzMwi) {" fullword ascii
    $s17 = "function ZQkt(tDTBE) {" fullword ascii
    $s18 = "function DTqq(MvFfB) {" fullword ascii
    $s19 = "function KvEpxKH(dvIZ,ORzVp) {" fullword ascii
    $s20 = "function UQkH(KHDNa) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160405_1e2944f9a9059e5f6bc55532919989c8 {
  meta:
    description = "datamaliciousorder - file 20160405_1e2944f9a9059e5f6bc55532919989c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "367abe40ad180ccb901ce5a04db686db9fbd01833a4c0412f4ac76ea65a2ff13"

  strings:
    $s1  = "return FVDHPfr[0] + FVDHPfr[2] + FVDHPfr[4] + \".F\" + FVDHPfr[7] + FVDHPfr[9] + FVDHPfr[12] + FVDHPfr[14];" fullword ascii
    $s2  = "var xb = true  , nvMU = Tnd[7] + Tnd[9] + Tnd[11];" fullword ascii
    $s3  = "var Tnd = (\"2.XMLHTTP oZswmsM fTgzl XML ream St HFqqGiEn AD JcFBBlJ O sSlX D\").split(\" \");" fullword ascii
    $s4  = "eHKJ.open(uhBfe,ZkbFR,false);" fullword ascii
    $s5  = "if(V>=B.length) {break;}" fullword ascii
    $s6  = "return new ActiveXObject(QYlJ);" fullword ascii
    $s7  = "function InRPM(qnpCho) {" fullword ascii
    $s8  = "function oBVKoSjux(cicnM) {" fullword ascii
    $s9  = "function Nmcb(byBJd) {" fullword ascii
    $s10 = "return HspeO.status;" fullword ascii
    $s11 = "function dgLZx(uujnOn) {" fullword ascii
    $s12 = "return gsi.size;" fullword ascii
    $s13 = "function RrwKKwec(zjSX) {" fullword ascii
    $s14 = "function pOhWMGZ(BsgP) {" fullword ascii
    $s15 = "function oWEG(DTjVy) {" fullword ascii
    $s16 = "function boavuyT(iphP,hTBRa) {" fullword ascii
    $s17 = "if (j >= vSYLh.length) {break;}" fullword ascii
    $s18 = "function WjxcxU(nzmjPTw) {" fullword ascii
    $s19 = "function vRae(HspeO) {" fullword ascii
    $s20 = "return iBAg;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
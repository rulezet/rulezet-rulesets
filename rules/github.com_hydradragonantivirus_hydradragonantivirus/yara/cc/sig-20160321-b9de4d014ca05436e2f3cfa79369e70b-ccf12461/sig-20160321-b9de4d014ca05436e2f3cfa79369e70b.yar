rule sig_20160321_b9de4d014ca05436e2f3cfa79369e70b {
  meta:
    description = "datamaliciousorder - file 20160321_b9de4d014ca05436e2f3cfa79369e70b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f748c0fa757633fe5a99b0bc985bb1d40541e782d1140f6e6790cbc762e6252f"

  strings:
    $s1  = "return WScript.CreateObject(gPQSv);" fullword ascii
    $s2  = "return pJfpnpX[0] + pJfpnpX[2] + pJfpnpX[4] + \".F\" + pJfpnpX[7] + pJfpnpX[9] + pJfpnpX[12] + pJfpnpX[14];" fullword ascii
    $s3  = "var aP = true  , rKfF = zSi[7] + zSi[9] + zSi[11];" fullword ascii
    $s4  = "var zSi = (\"2.XMLHTTP CFtQYsA SHVwL XML ream St feJiRaWw AD zMhPJTb O txzW D\").split(\" \");" fullword ascii
    $s5  = "var pJfpnpX = DQirq(EPpzokNbie+\" \"+\"System jT DMgXc Obj DtmyKB ect kNCYvUP sumYT\", \" \");" fullword ascii
    $s6  = "UHgHZ.open(qrIIZ,CSxZk,false);" fullword ascii
    $s7  = "cZI = V; break; " fullword ascii
    $s8  = "function rORx(KRShe) {" fullword ascii
    $s9  = "function IEJu(nkAol) {" fullword ascii
    $s10 = "function wQkfGVzT(RESR) {" fullword ascii
    $s11 = "return EAGPx;" fullword ascii
    $s12 = "return QxE.split(BQJZy);" fullword ascii
    $s13 = "return HaS.size;" fullword ascii
    $s14 = "function sysOeAzD(HaS) {" fullword ascii
    $s15 = "function ZhtT(yZtto) {" fullword ascii
    $s16 = "return ZovKW.status;" fullword ascii
    $s17 = "return tDdInIr(rC,OFRPa[874-868]+OFRPa[544-537]+OFRPa[672-664]);" fullword ascii
    $s18 = "function gXLcn(dKpuwV) {" fullword ascii
    $s19 = "return pzyJ[NotKwd[0]];" fullword ascii
    $s20 = "function tDdInIr(VcWq,JomrF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
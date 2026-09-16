rule sig_20160404_0b38174cebfac823be20889f62ce2447 {
  meta:
    description = "datamaliciousorder - file 20160404_0b38174cebfac823be20889f62ce2447.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dacfe44f03eb64f6530425ad2b88660716d0cb0ebc9beb93538ae482a038731"

  strings:
    $s1  = "var FUX = (\"2.XMLHTTP znROCmx Ljign XML ream St sEOuROhX AD JLogYYP O Pnsr D\").split(\" \");" fullword ascii
    $s2  = "return KYNMaYV[0] + KYNMaYV[2] + KYNMaYV[4] + \".F\" + KYNMaYV[7] + KYNMaYV[9] + KYNMaYV[12] + KYNMaYV[14];" fullword ascii
    $s3  = "var fA = true  , OoAh = FUX[7] + FUX[9] + FUX[11];" fullword ascii
    $s4  = "var KYNMaYV = CugFZ(UrZnCFJSUy+\" \"+\"System Kd zeYgH Obj Lcuctn ect ypLuRuN ilDsQ\", \" \");" fullword ascii
    $s5  = "fSAR.open(rMkuP,VbmQh,false);" fullword ascii
    $s6  = "function sjpjjQLD(PbC) {" fullword ascii
    $s7  = "if(p>=Z.length) {break;}" fullword ascii
    $s8  = "function JpIVro(oeSGJPb) {" fullword ascii
    $s9  = "function VGqc(daaOZ,PGVNK) {" fullword ascii
    $s10 = "return DEQ.split(rvaeZ);" fullword ascii
    $s11 = "function CugFZ(DEQ,rvaeZ) {" fullword ascii
    $s12 = "function PNJT(xxuRT,VbmQh,rMkuP) {" fullword ascii
    $s13 = "function PYArXMU(pMVh) {" fullword ascii
    $s14 = "function EWjMjbj(rplF,MINFU) {" fullword ascii
    $s15 = "function Tmxfi(GVXbDK) {" fullword ascii
    $s16 = "var gqbMEoU = \"nNWFYr*GWQ*pt.S\"+\"hell*WjFCosi*Scri*\";" fullword ascii
    $s17 = "bCu = p; break; " fullword ascii
    $s18 = "function EeZv(mzkuk) {" fullword ascii
    $s19 = "if (V >= AxGst.length) {break;}" fullword ascii
    $s20 = "return \"ZCOWaAazImagwl\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
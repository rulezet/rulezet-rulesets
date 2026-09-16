rule sig_20160321_586eefaeb327e1c865a8bb71e892d81b {
  meta:
    description = "datamaliciousorder - file 20160321_586eefaeb327e1c865a8bb71e892d81b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c588f04c6fc82b445d45611271d240c7c33750feeaf15f0ef054f6796f53cdf6"

  strings:
    $s1  = "return WScript.CreateObject(MLVwB);" fullword ascii
    $s2  = "return LPeeLKp[0] + LPeeLKp[2] + LPeeLKp[4] + \".F\" + LPeeLKp[7] + LPeeLKp[9] + LPeeLKp[12] + LPeeLKp[14];" fullword ascii
    $s3  = "var jN = true  , ZsQa = PcM[7] + PcM[9] + PcM[11];" fullword ascii
    $s4  = "var PcM = (\"2.XMLHTTP ZyspGzR sCWPH XML ream St wzCVXukJ AD uFVIneN O zJSb D\").split(\" \");" fullword ascii
    $s5  = "var LPeeLKp = rBFYL(WnppOMSCDg+\" \"+\"System wN teMFH Obj DrekLj ect sPQqeKj dZpth\", \" \");" fullword ascii
    $s6  = "function ctYGNnUG(UPe) {" fullword ascii
    $s7  = "function PLaM(MLVwB) {" fullword ascii
    $s8  = "function VkiFh(JRSKXK) {" fullword ascii
    $s9  = "function yAbvpHT(gNnp) {" fullword ascii
    $s10 = "return new ActiveXObject(JRSKXK);" fullword ascii
    $s11 = "function ALjFV(yDeqWr) {" fullword ascii
    $s12 = "function GhVB(HQSqd) {" fullword ascii
    $s13 = "function bkvARvgAI(sehBnjzDoPu) {" fullword ascii
    $s14 = "function Xjcj(dudZt,ACpll) {" fullword ascii
    $s15 = "function wHSOIqTQr(VTaQy) {" fullword ascii
    $s16 = "return UPe.size;" fullword ascii
    $s17 = "return rltYp;" fullword ascii
    $s18 = "function WUDx(TSZgk) {" fullword ascii
    $s19 = "if(o>=r.length) {break;}" fullword ascii
    $s20 = "return XoLztRu(af,lLqJD[631-625]+lLqJD[119-112]+lLqJD[635-627]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
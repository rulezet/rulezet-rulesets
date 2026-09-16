rule sig_20160310_5c0934e7e7dea2b2f88ef4cfe9d3d109 {
  meta:
    description = "datamaliciousorder - file 20160310_5c0934e7e7dea2b2f88ef4cfe9d3d109.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ad4e1fe2b0371472a312f9b64c2a48c18206fe8df199897343fc3a12e6eddf4"

  strings:
    $s1  = "var rhZYl = \"zFRGIt fzG pt.Shell KyKvliu Scri DIng %TE MP% \\\\ AcCsGsqAS\".split(\" \");" fullword ascii
    $s2  = "var FV = true  , Scft = sos[7] + sos[9] + sos[11];" fullword ascii
    $s3  = "return WLECPJv[0] + WLECPJv[2] + WLECPJv[4] + \".F\" + WLECPJv[7] + WLECPJv[9] + WLECPJv[12] + WLECPJv[14];" fullword ascii
    $s4  = "var sos = (\"2.XMLHTTP RJDqoGT fyuDa XML ream St MTSuCroZ AD kdbEJrj O UyHX D\").split(\" \");" fullword ascii
    $s5  = "GJzEI.open(pCniU,bMSgY,false);" fullword ascii
    $s6  = "var WLECPJv = \"Sc iQxjoeX r gIrEZoITa ipting iXyVPHW gkc ile LmWSfiTEFlEWBs System sy uoDVS Obj DDrLcR ect uLZffXP\".split(\" " ascii
    $s7  = "function whQPgfA(WlKc,Twdpz) {" fullword ascii
    $s8  = "function TBdJBeof() {" fullword ascii
    $s9  = "DuF = X; break; " fullword ascii
    $s10 = "function jbgMsPauw(lDVAN,HrYok,PUvhw,KsmD) {" fullword ascii
    $s11 = "function XwhM(zcjgy,Xdlhb) {" fullword ascii
    $s12 = "function VavKqJpKi(WZVdvILGCGc) {" fullword ascii
    $s13 = "function cKwa(VMMvq) {" fullword ascii
    $s14 = "function gmVP(RUluK) {" fullword ascii
    $s15 = "function sPNV(kXzhW) {" fullword ascii
    $s16 = "return WlKc.ExpandEnvironmentStrings(Twdpz);" fullword ascii
    $s17 = "return mxhnho.position=410-410;" fullword ascii
    $s18 = "if (FTOcC == 590-390){return true;} else {return false;}" fullword ascii
    $s19 = "return qlQ.size;" fullword ascii
    $s20 = "function HNdPc(inZsHg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
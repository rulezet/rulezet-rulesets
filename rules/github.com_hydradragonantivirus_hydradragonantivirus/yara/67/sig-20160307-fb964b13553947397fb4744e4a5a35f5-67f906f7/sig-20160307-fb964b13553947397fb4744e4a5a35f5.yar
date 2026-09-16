rule sig_20160307_fb964b13553947397fb4744e4a5a35f5 {
  meta:
    description = "datamaliciousorder - file 20160307_fb964b13553947397fb4744e4a5a35f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "499bd460fc780e77aeca83840c540e82c91fd67a4f263b5518c24c80c0508356"

  strings:
    $s1  = "return CtzFwzr[0] + CtzFwzr[2] + CtzFwzr[4] + \".F\" + CtzFwzr[7] + CtzFwzr[9] + CtzFwzr[12] + CtzFwzr[14];" fullword ascii
    $s2  = "var Mo = true  , OmIq = axL[7] + axL[9] + axL[11];" fullword ascii
    $s3  = "var axL = (\"2.XMLHTTP zXQCskB CELks XML ream St WvcoHGVk AD NGKdBeu O vink D\").split(\" \");" fullword ascii
    $s4  = "VtZiK.open(OfhQd,hyytR,false);" fullword ascii
    $s5  = "var CtzFwzr = \"Sc gpGNzZR r zPceMBrMC ipting mWMPohq Ese ile edWAXDcwLiCJBy System pp VstdU Obj dOyOTP ect aTTnjjt\".split(\" " ascii
    $s6  = "function Ztht(xtnGd) {" fullword ascii
    $s7  = "function FZGIwEWq(EaZ) {" fullword ascii
    $s8  = "return DOzhG.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s9  = "function QRsUX(jLIZMd) {" fullword ascii
    $s10 = "function nwjF(xsfOR,DKNuO) {" fullword ascii
    $s11 = "if (FzUQE > 175919-470){return true;} else {return false;}" fullword ascii
    $s12 = "if (Q >= MrBvk.length) {break;}" fullword ascii
    $s13 = "wnO = u; break; " fullword ascii
    $s14 = "function YynN(VtZiK,hyytR,OfhQd) {" fullword ascii
    $s15 = "function Mfqc(FzUQE) {" fullword ascii
    $s16 = "if (((new Date())>0,7613313888)) {" fullword ascii
    $s17 = "if(u>=w.length) {break;}" fullword ascii
    $s18 = "function TxBkKJN(FNZA) {" fullword ascii
    $s19 = "function xtGD(MrBvk) {" fullword ascii
    $s20 = "return YRaNTLj" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
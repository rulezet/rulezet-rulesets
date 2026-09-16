rule sig_20160321_4f124021d77f65c2132dc7b2a824da1b {
  meta:
    description = "datamaliciousorder - file 20160321_4f124021d77f65c2132dc7b2a824da1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3d1c142fb44547b01ba88561e1acd9b7a51a4d3e2ca7de4a5a9a61ae7d78e84"

  strings:
    $s1  = "return WScript.CreateObject(zazqy);" fullword ascii
    $s2  = "return diaNnjC[0] + diaNnjC[2] + diaNnjC[4] + \".F\" + diaNnjC[7] + diaNnjC[9] + diaNnjC[12] + diaNnjC[14];" fullword ascii
    $s3  = "var MR = true  , oXic = YBX[7] + YBX[9] + YBX[11];" fullword ascii
    $s4  = "xefKW.open(aQTAJ,XtpnN,false);" fullword ascii
    $s5  = "var YBX = (\"2.XMLHTTP jVXddoH ffaLt XML ream St HYGmXxrp AD gsriywS O vmNv D\").split(\" \");" fullword ascii
    $s6  = "var diaNnjC = EVIMy(qnCUVkxDLg+\" \"+\"System wt atMUD Obj njBcnI ect eBDdIoR KGvVR\", \" \");" fullword ascii
    $s7  = "return iuXLMp.position=824-824;" fullword ascii
    $s8  = "function Bbsf(rryEs,mfxAQ) {" fullword ascii
    $s9  = "yFe = X; break; " fullword ascii
    $s10 = "if (xeseD == 429-229){return true;} else {return false;}" fullword ascii
    $s11 = "function uYzwhOPz(tWIv) {" fullword ascii
    $s12 = "if (MFjsz > 190692-879){return true;} else {return false;}" fullword ascii
    $s13 = "return bEG.split(NQhGd);" fullword ascii
    $s14 = "function EVIMy(bEG,NQhGd) {" fullword ascii
    $s15 = "function VBZC(fiYRs) {" fullword ascii
    $s16 = "return fiYRs.status;" fullword ascii
    $s17 = "function kCObR(XdGPJs) {" fullword ascii
    $s18 = "return new ActiveXObject(XdGPJs);" fullword ascii
    $s19 = "function JtsTAKl(Nlcr) {" fullword ascii
    $s20 = "return gAaYVrE(iQ,BfuRj[195-189]+BfuRj[308-301]+BfuRj[641-633]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
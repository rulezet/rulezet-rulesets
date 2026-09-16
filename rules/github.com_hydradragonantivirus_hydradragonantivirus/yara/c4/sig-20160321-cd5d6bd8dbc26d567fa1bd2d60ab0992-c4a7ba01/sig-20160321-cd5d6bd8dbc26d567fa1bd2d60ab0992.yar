rule sig_20160321_cd5d6bd8dbc26d567fa1bd2d60ab0992 {
  meta:
    description = "datamaliciousorder - file 20160321_cd5d6bd8dbc26d567fa1bd2d60ab0992.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fda1c53ddab54c8dbc3d5ec7a3b55bc243d09452fd35b9ef664f4d496d77a2"

  strings:
    $s1  = "return WScript.CreateObject(TwPtQ);" fullword ascii
    $s2  = "return OFVlcmB[0] + OFVlcmB[2] + OFVlcmB[4] + \".F\" + OFVlcmB[7] + OFVlcmB[9] + OFVlcmB[12] + OFVlcmB[14];" fullword ascii
    $s3  = "var Km = true  , jFbU = XGD[7] + XGD[9] + XGD[11];" fullword ascii
    $s4  = "SIWrv.open(vsfZU,bahbf,false);" fullword ascii
    $s5  = "var XGD = (\"2.XMLHTTP gnkIQRz sVBvz XML ream St IBFFtJKX AD EgTIgVJ O JjlR D\").split(\" \");" fullword ascii
    $s6  = "var OFVlcmB = KFaRF(cZruExjpMv+\" \"+\"System iL vXYsp Obj nlAIZL ect JVOfPgo FhfMU\", \" \");" fullword ascii
    $s7  = "return cdyO.ExpandEnvironmentStrings(TdZMw);" fullword ascii
    $s8  = "return RxIBepp(uL,NxSSb[177-171]+NxSSb[351-344]+NxSSb[973-965]);" fullword ascii
    $s9  = "function iigM(TwPtQ) {" fullword ascii
    $s10 = "function tRNWAYaqG(cgneo) {" fullword ascii
    $s11 = "gsw = F; break; " fullword ascii
    $s12 = "function GMEdd(RIkTut) {" fullword ascii
    $s13 = "if (DCVcf == 644-444){return true;} else {return false;}" fullword ascii
    $s14 = "return hQb.size;" fullword ascii
    $s15 = "function zoMTeEsM(Ezqa) {" fullword ascii
    $s16 = "function zcFWn(XWfHSi) {" fullword ascii
    $s17 = "if (N >= JUFoX.length) {break;}" fullword ascii
    $s18 = "if(F>=T.length) {break;}" fullword ascii
    $s19 = "function icMN(DCVcf) {" fullword ascii
    $s20 = "function wwWaiKZv(hQb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160307_17a5ea1222cd7f0ae467cfe8a5b81d0a {
  meta:
    description = "datamaliciousorder - file 20160307_17a5ea1222cd7f0ae467cfe8a5b81d0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6948f5eca66099c71b9b7083dd5127ff4fb2e5137b3ee263224b3ba571f37049"

  strings:
    $s1  = "return taADIWW[0] + taADIWW[2] + taADIWW[4] + \".F\" + taADIWW[7] + taADIWW[9] + taADIWW[12] + taADIWW[14];" fullword ascii
    $s2  = "var Fc = true  , iVIq = qIv[7] + qIv[9] + qIv[11];" fullword ascii
    $s3  = "function Jsux(hItMP) {" fullword ascii
    $s4  = "if (hItMP == 458-258){return true;} else {return false;}" fullword ascii
    $s5  = "PSIIS.open(wPXEm,ReSmG,false);" fullword ascii
    $s6  = "var taADIWW = \"Sc ZsrNpgq r ZWZqKbhlq ipting lkJUcer MdR ile LMpyMSjgsRMZPH System Qe GCKnE Obj RzLsiz ect pKSqNOG\".split(\" " ascii
    $s7  = "var qIv = (\"2.XMLHTTP cgeZnic RVxHF XML ream St JeXLleDP AD GAzXVYG O NcTj D\").split(\" \");" fullword ascii
    $s8  = "ubU = i; break; " fullword ascii
    $s9  = "function pEQF(QbsHg) {" fullword ascii
    $s10 = "return tMReM.status;" fullword ascii
    $s11 = "function dlolLJEJ(Vlv) {" fullword ascii
    $s12 = "function IUqw(fQRfJ) {" fullword ascii
    $s13 = "function GnDo(NPYXN,zVfSj) {" fullword ascii
    $s14 = "return new ActiveXObject(boIrHK);" fullword ascii
    $s15 = "function wSuqJvn(lAUv) {" fullword ascii
    $s16 = "function ppVS(kvkzL) {" fullword ascii
    $s17 = "function iswa(RxzxK) {" fullword ascii
    $s18 = "function qPMNQSVjD(SdDVsrFYCRr) {" fullword ascii
    $s19 = "if (fQRfJ > 169333-580){return true;} else {return false;}" fullword ascii
    $s20 = "if (I >= RxzxK.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
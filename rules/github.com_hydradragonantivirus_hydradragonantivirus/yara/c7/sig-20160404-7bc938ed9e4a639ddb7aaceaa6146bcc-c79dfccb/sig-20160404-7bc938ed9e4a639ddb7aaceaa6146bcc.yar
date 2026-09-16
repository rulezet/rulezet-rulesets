rule sig_20160404_7bc938ed9e4a639ddb7aaceaa6146bcc {
  meta:
    description = "datamaliciousorder - file 20160404_7bc938ed9e4a639ddb7aaceaa6146bcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77c4735646a541ce366e27e2df9dd173e401776261440ff94aa5dab3c4e450d5"

  strings:
    $s1  = "return gWKqgbP[0] + gWKqgbP[2] + gWKqgbP[4] + \".F\" + gWKqgbP[7] + gWKqgbP[9] + gWKqgbP[12] + gWKqgbP[14];" fullword ascii
    $s2  = "var kX = true  , PeIo = usj[7] + usj[9] + usj[11];" fullword ascii
    $s3  = "var usj = (\"2.XMLHTTP cPncPDH MvQaL XML ream St GXismbKP AD GiqFONR O eySV D\").split(\" \");" fullword ascii
    $s4  = "var gWKqgbP = idCUF(ccXzKCsMiR+\" \"+\"System Ru FJQhX Obj zLXJpl ect diRamIB THwJV\", \" \");" fullword ascii
    $s5  = "IJvH.open(tsPDG,jNAGo,false);" fullword ascii
    $s6  = "return lpfrY.status;" fullword ascii
    $s7  = "return rQuj;" fullword ascii
    $s8  = "function BDBvY(tygcnw) {" fullword ascii
    $s9  = "return rbyXAnr;" fullword ascii
    $s10 = "return \"KOVFlnBUyyGhLb\";" fullword ascii
    $s11 = "function OYVl(ktGJe) {" fullword ascii
    $s12 = "function FErlTjHbk(ojEaDExKmtf) {" fullword ascii
    $s13 = "return HsGE[TAKGUJ[0]];" fullword ascii
    $s14 = "function GvLyMlFk(XDgB) {" fullword ascii
    $s15 = "function NMRB(EufDi) {" fullword ascii
    $s16 = "return new ActiveXObject(PDFp);" fullword ascii
    $s17 = "function IQzL(NruJe) {" fullword ascii
    $s18 = "var zppERyK = \"wWQVZL*kod*pt.S\"+\"hell*ygPPmCn*Scri*\";" fullword ascii
    $s19 = "if (kufhK == 1181-981){return true;} else {return false;}" fullword ascii
    $s20 = "return KnM.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160404_fae326c8fface268bb28014c6f6d5782 {
  meta:
    description = "datamaliciousorder - file 20160404_fae326c8fface268bb28014c6f6d5782.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ddab46e7ee47892e92b46156f324dd28e5275eadce2d31921c5fff343841b8"

  strings:
    $s1  = "var OY = true  , MuTE = PDQ[7] + PDQ[9] + PDQ[11];" fullword ascii
    $s2  = "var Ajv = iUZn(MuTE + \"B.\" + PDQ[5]+(382499, PDQ[4]));" fullword ascii
    $s3  = "return AaEEXDz[0] + AaEEXDz[2] + AaEEXDz[4] + \".F\" + AaEEXDz[7] + AaEEXDz[9] + AaEEXDz[12] + AaEEXDz[14];" fullword ascii
    $s4  = "var AaEEXDz = QeRHp(pahBicOqqU+\" \"+\"System ie hNGcN Obj iedkWK ect Mmyynwt ntIWg\", \" \");" fullword ascii
    $s5  = "rDoE.open(QIxUe,ihrGV,false);" fullword ascii
    $s6  = "var PDQ = (\"2.XMLHTTP OFWdWuW QkQos XML ream St jZUWMVjz AD ViNNyxn O RyGe D\").split(\" \");" fullword ascii
    $s7  = "if(d>=q.length) {break;}" fullword ascii
    $s8  = "return \"YsfwhWpcPGbozE\";" fullword ascii
    $s9  = "function hTfTIS(xaxaEXC) {" fullword ascii
    $s10 = "if (ZUzlI == 1157-957){return true;} else {return false;}" fullword ascii
    $s11 = "function okGm(pdfQp) {" fullword ascii
    $s12 = "function vixJb(pAKORv) {" fullword ascii
    $s13 = "return NoNv;" fullword ascii
    $s14 = "var yLjlxJP = \"EtweUj*Gmi*pt.S\"+\"hell*bBSmYKK*Scri*\";" fullword ascii
    $s15 = "function vqqoL(VPtSIe) {" fullword ascii
    $s16 = "function CFkEoY(YlUa,smszzj) {" fullword ascii
    $s17 = "if (pdfQp > 173579-196){return true;} else {return false;}" fullword ascii
    $s18 = "function skoe(ujBtH) {" fullword ascii
    $s19 = "return RDyXTOm;" fullword ascii
    $s20 = "return KExNuwR;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
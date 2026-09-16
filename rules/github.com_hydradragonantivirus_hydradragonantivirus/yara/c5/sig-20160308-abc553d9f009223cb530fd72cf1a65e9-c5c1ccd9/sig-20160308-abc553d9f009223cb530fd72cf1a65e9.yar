rule sig_20160308_abc553d9f009223cb530fd72cf1a65e9 {
  meta:
    description = "datamaliciousorder - file 20160308_abc553d9f009223cb530fd72cf1a65e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "490dd7c21a9ed72c47bece03b9637a7efd86ef02ccda64f61500425b16c82aaf"

  strings:
    $s1  = "var lv = true  , ggWV = yVd[7] + yVd[9] + yVd[11];" fullword ascii
    $s2  = "return YZdBrtx[0] + YZdBrtx[2] + YZdBrtx[4] + \".F\" + YZdBrtx[7] + YZdBrtx[9] + YZdBrtx[12] + YZdBrtx[14];" fullword ascii
    $s3  = "var yVd = (\"2.XMLHTTP hUKPqQg oHBdg XML ream St VUIUeUOk AD VAlThLe O gGMV D\").split(\" \");" fullword ascii
    $s4  = "nWyTo.open(HjJWZ,PLLjK,false);" fullword ascii
    $s5  = "var YZdBrtx = \"Sc SexRaIb r MqAulkSXt ipting VvBZESo LMe ile WGxbvsvxFgVunI System Xx eSOWz Obj MJZyNH ect wacxNrs\".split(\" " ascii
    $s6  = "function wKpb(nWyTo,PLLjK,HjJWZ) {" fullword ascii
    $s7  = "function mMdb(jqRbV) {" fullword ascii
    $s8  = "return jqRbV.status;" fullword ascii
    $s9  = "lwq = r; break; " fullword ascii
    $s10 = "function FnGZ(TohrU) {" fullword ascii
    $s11 = "function kIkzImcSy(fGwwv,uvIoe,aQpze,QEBu) {" fullword ascii
    $s12 = "if (M >= nRxgn.length) {break;}" fullword ascii
    $s13 = "return NFWS.responseBody;" fullword ascii
    $s14 = "if (tsfuR > 200185-615){return true;} else {return false;}" fullword ascii
    $s15 = "if(r>=K.length) {break;}" fullword ascii
    $s16 = "return zKmglEF" fullword ascii
    $s17 = "return QIC.size;" fullword ascii
    $s18 = "function VBdB(ZweyR) {" fullword ascii
    $s19 = "if (TohrU == 413-213){return true;} else {return false;}" fullword ascii
    $s20 = "function LBUHwUfT() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
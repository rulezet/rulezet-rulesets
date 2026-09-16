rule sig_20160312_35b9d2b8adbe3ab5002030f84b31440d {
  meta:
    description = "datamaliciousorder - file 20160312_35b9d2b8adbe3ab5002030f84b31440d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1162bd7c0c9f9608a7c142cbf4bfa70adc3b194a3ba6734c0b4be3ee4521614"

  strings:
    $s1  = "return nEwHQZq[0] + nEwHQZq[2] + nEwHQZq[4] + \".F\" + nEwHQZq[7] + nEwHQZq[9] + nEwHQZq[12] + nEwHQZq[14];" fullword ascii
    $s2  = "var Ux = true  , vnPK = azc[7] + azc[9] + azc[11];" fullword ascii
    $s3  = "var azc = (\"2.XMLHTTP SBXBheM wQFHf XML ream St daTEXzjW AD tifAOSG O Ggtw D\").split(\" \");" fullword ascii
    $s4  = "fiBfk.open(cXYNY,zfuOD,false);" fullword ascii
    $s5  = "return mEBeM;" fullword ascii
    $s6  = "return kDYa.ExpandEnvironmentStrings(qbMww);" fullword ascii
    $s7  = "return phE.size;" fullword ascii
    $s8  = "function mFFW(lAmVP) {" fullword ascii
    $s9  = "function cydrT(rMnzYR) {" fullword ascii
    $s10 = "if (B >= cvIxo.length) {break;}" fullword ascii
    $s11 = "return new ActiveXObject(yBZKPY);" fullword ascii
    $s12 = "CnS = O; break; " fullword ascii
    $s13 = "return ljJd.responseBody;" fullword ascii
    $s14 = "function tAOH(DugSX) {" fullword ascii
    $s15 = "function jhSvK(yBZKPY) {" fullword ascii
    $s16 = "function fKGc(DfHeG,OhFbk) {" fullword ascii
    $s17 = "function ZHzQ(UZbps,USSae) {" fullword ascii
    $s18 = "if (bGvPI > 187129-560){return true;} else {return false;}" fullword ascii
    $s19 = "function FYiA(cvIxo) {" fullword ascii
    $s20 = "function yUPs(bGvPI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
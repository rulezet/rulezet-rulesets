rule sig_20160405_c5a0ea208c8571bf63bbdd50170f382b {
  meta:
    description = "datamaliciousorder - file 20160405_c5a0ea208c8571bf63bbdd50170f382b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e0d73f3d2557db083d5c1bcf5737176e79f4480925f8df8764b7e39431dea1f"

  strings:
    $s1  = "var ITw = (\"2.XMLHTTP AYpFVvX UUvNN XML ream St XGbmPXkX AD hcDHngc O FTPE D\").split(\" \");" fullword ascii
    $s2  = "var PA = true  , wmVx = ITw[7] + ITw[9] + ITw[11];" fullword ascii
    $s3  = "return KpJbPDb[0] + KpJbPDb[2] + KpJbPDb[4] + \".F\" + KpJbPDb[7] + KpJbPDb[9] + KpJbPDb[12] + KpJbPDb[14];" fullword ascii
    $s4  = "LZeu.open(rYdok,UHtZf,false);" fullword ascii
    $s5  = "return dEX.split(nTqTW);" fullword ascii
    $s6  = "return WLPkW.status;" fullword ascii
    $s7  = "function NWFWKsdu(lEI) {" fullword ascii
    $s8  = "function xlUtEjH(pqrM) {" fullword ascii
    $s9  = "function JByV(wCLGy) {" fullword ascii
    $s10 = "return KVRbvqc[0];" fullword ascii
    $s11 = "function pqAal(dEX,nTqTW) {" fullword ascii
    $s12 = "if (F >= ilslV.length) {break;}" fullword ascii
    $s13 = "if (RVgNF > 182296-328){return true;} else {return false;}" fullword ascii
    $s14 = "return lEI.size;" fullword ascii
    $s15 = "function uNXdC(FqQRAYJe,iUXf) {" fullword ascii
    $s16 = "function bVSpvFsX(XWrV) {" fullword ascii
    $s17 = "function asmlIG(YzVq,VPwnyw) {" fullword ascii
    $s18 = "return MFsg;" fullword ascii
    $s19 = "function yJyuKf(ZqSvEad) {" fullword ascii
    $s20 = "return \"mfvhuPeuDhtDLj\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
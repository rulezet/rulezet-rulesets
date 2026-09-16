rule sig_20160405_69a7500b11d0c556fd5e99d18af6a849 {
  meta:
    description = "datamaliciousorder - file 20160405_69a7500b11d0c556fd5e99d18af6a849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d89ddf6f562c7603edea6aa076741fd4c648320a4e20bd0ef6f1537a5b04ac14"

  strings:
    $s1  = "return xYAjkby[0] + xYAjkby[2] + xYAjkby[4] + \".F\" + xYAjkby[7] + xYAjkby[9] + xYAjkby[12] + xYAjkby[14];" fullword ascii
    $s2  = "var kx = true  , xADZ = cXx[7] + cXx[9] + cXx[11];" fullword ascii
    $s3  = "oeiy.open(LLzud,hMGuR,false);" fullword ascii
    $s4  = "var cXx = (\"2.XMLHTTP NMjxbYj LgUYv XML ream St eoWuQvIc AD ZecQROE O DLzp D\").split(\" \");" fullword ascii
    $s5  = "return OdH.split(LcliH);" fullword ascii
    $s6  = "function BqFnZIQO(weSm) {" fullword ascii
    $s7  = "function pcZQkrkiL(zpbrx) {" fullword ascii
    $s8  = "return BVvrKJy(iJ,mwLEh[196-190]+mwLEh[802-795]+mwLEh[672-664]);" fullword ascii
    $s9  = "if (J >= LzkoO.length) {break;}" fullword ascii
    $s10 = "return ApOpWQl[0];" fullword ascii
    $s11 = "if (hwDpS > 187981-183){return true;} else {return false;}" fullword ascii
    $s12 = "return CIWPt.status;" fullword ascii
    $s13 = "if(b>=m.length) {break;}" fullword ascii
    $s14 = "function GjZeRccu(OQA) {" fullword ascii
    $s15 = "function kioCw(orRtXi) {" fullword ascii
    $s16 = "function Nuhx(mYfnY) {" fullword ascii
    $s17 = "return gaDgMOT;" fullword ascii
    $s18 = "var lKXxXGe = \"HomaIr*nYn*pt.S\"+\"hell*STtuJHj*Scri*\";" fullword ascii
    $s19 = "function fNngx(iYqVMcsF,zfyj) {" fullword ascii
    $s20 = "function AGUqDC(tUKQ,yfqlxC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
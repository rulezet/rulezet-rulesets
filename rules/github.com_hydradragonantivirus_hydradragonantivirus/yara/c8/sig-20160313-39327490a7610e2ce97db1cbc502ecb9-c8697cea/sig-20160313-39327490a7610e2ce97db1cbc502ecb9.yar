rule sig_20160313_39327490a7610e2ce97db1cbc502ecb9 {
  meta:
    description = "datamaliciousorder - file 20160313_39327490a7610e2ce97db1cbc502ecb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3c7124389f86f1309574db9ad1f22b68359300c27dc51f4fc3fdd8d9a23622a"

  strings:
    $s1  = "return pTkcqEF[0] + pTkcqEF[2] + pTkcqEF[4] + \".F\" + pTkcqEF[7] + pTkcqEF[9] + pTkcqEF[12] + pTkcqEF[14];" fullword ascii
    $s2  = "var bC = true  , eaUh = aRP[7] + aRP[9] + aRP[11];" fullword ascii
    $s3  = "var aRP = (\"2.XMLHTTP QuuwRnI rMUbh XML ream St LWMIBOIW AD sdzvQHm O bHUj D\").split(\" \");" fullword ascii
    $s4  = "var pTkcqEF = \"Sc kiEAmxk r FBPmAknlL ipting XTtqbhb kzS ile wlkMParCqgbcoK System Fs bUzxO Obj kZXjyV ect kwgHKWF\".split(\" " ascii
    $s5  = "sPJPu.open(AoNgH,wETEI,false);" fullword ascii
    $s6  = "function cDjvr(DRRJMg) {" fullword ascii
    $s7  = "function siqvcdwZ(YMZ) {" fullword ascii
    $s8  = "function KJAD(aBKUZ) {" fullword ascii
    $s9  = "return vOTD.responseBody;" fullword ascii
    $s10 = "function ugfkF(grdyfk) {" fullword ascii
    $s11 = "function ehgy(Leuww) {" fullword ascii
    $s12 = "return YMZ.size;" fullword ascii
    $s13 = "function XdqQ(mClXn) {" fullword ascii
    $s14 = "return DhPbi;" fullword ascii
    $s15 = "if (aBKUZ == 582-382){return true;} else {return false;}" fullword ascii
    $s16 = "function JZNt(cdIWv,vYDTp) {" fullword ascii
    $s17 = "function fiNS(RHUMQ) {" fullword ascii
    $s18 = "return new ActiveXObject(grdyfk);" fullword ascii
    $s19 = "return nmyw.ExpandEnvironmentStrings(BgYYA);" fullword ascii
    $s20 = "function oHdz(UNjEz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
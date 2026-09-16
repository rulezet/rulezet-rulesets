rule sig_20160301_eeb6f70db031db4f097433cd4c6a2e3a {
  meta:
    description = "datamaliciousorder - file 20160301_eeb6f70db031db4f097433cd4c6a2e3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0240d70b41064b9aebf747c9ffa96a90db5cbcf6e94cd829cdcda4cfb0fb4b29"

  strings:
    $s1  = "var Em = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(dhuZm);" fullword ascii
    $s3  = "return new ActiveXObject(mqGgeT);" fullword ascii
    $s4  = "function aFnhS(mqGgeT) {" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + FILUKMr + \".F\" + uZBBKkqwwH + bhxTc + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "var zy = true  , VyKj = EgX[7] + \"\" + EgX[9];" fullword ascii
    $s7  = "var EgX = (FaU + \"TTP\" + \" fhexCUD mcNbs XML ream St zAymzQOV AD uXVcjBu OD\").split(\" \");" fullword ascii
    $s8  = "GqjCu.open(xLwBV,XdBEV,false);" fullword ascii
    $s9  = "function jJQlnYWG() {" fullword ascii
    $s10 = "function qMFerpBlC(rRyEB,BCdmX,uNZOX) {" fullword ascii
    $s11 = "function uAZZjXxHx(YPbZsvwkJVz) {" fullword ascii
    $s12 = "if(E>=l.length) {break;}" fullword ascii
    $s13 = "return nXigL;" fullword ascii
    $s14 = "function HtOF(HkqQX) {" fullword ascii
    $s15 = "YKg = E; break; " fullword ascii
    $s16 = "function LqvZ(Jvdwr) {" fullword ascii
    $s17 = "function OAik(GFZoh) {" fullword ascii
    $s18 = "if (juJCD > 188072-673){return true;} else {return false;}" fullword ascii
    $s19 = "function Oxcw(juJCD) {" fullword ascii
    $s20 = "function jhvg(XGses) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
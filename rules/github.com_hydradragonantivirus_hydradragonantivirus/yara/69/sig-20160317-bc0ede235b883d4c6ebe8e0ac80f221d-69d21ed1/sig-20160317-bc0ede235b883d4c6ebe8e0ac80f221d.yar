rule sig_20160317_bc0ede235b883d4c6ebe8e0ac80f221d {
  meta:
    description = "datamaliciousorder - file 20160317_bc0ede235b883d4c6ebe8e0ac80f221d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3caf3b5f90774e72356ddecd1621991d11701dba6a04694853df503616d089d6"

  strings:
    $s1  = "var eFo = \"ej!5qkRt\".charAt(2);var oh = \"ain\";var ST = \"\\x79 ag\";var cz = \", tr\";var XsD = \"\\x61\\x73\\x65\";var m1 =" ascii
    $s2  = "}}if (Xg){dSFiU = jMSGg[(e) + (iI) + (WFE) + (Fcu) + (a) + (A) + (ueXMM) + (f) + (r)]((sRKa) + (CY) + (grvKK)) + (Ha) + (hBMrY) " ascii
    $s3  = "MkqR);}else{WScript.Echo((hF) + (m1) + (XsD) + (cz) + (ST) + (oh) + (eFo));}" fullword ascii
    $s4  = "var TG = \"Crea\";jMSGg = WScript[(TG) + (txzTr) + (xxQt) + (Dhm)]((Cc) + (ojRf) + (pcl));function nNh(L){jMSGg[(pkOa)](L, 0, 0)" ascii
    $s5  = "return fXfu - Zzeev;}var Xg = false;for (var RJjN = 0; RJjN < LrIO() * 1; RJjN++){" fullword ascii
    $s6  = "arkQ) + (CnM) + (Si) + (k) + (rJyDb) + (FuP) + (rsLvw) + (Qui) + (HR) + (mHHE) + (bAWk) + (cHV), false);vMI[(vt)]();while (vMI[(" ascii
    $s7  = "var gn = new this[(kiV) + (oJP)]();" fullword ascii
    $s8  = ";function w(){return (ozZAS) + (m) + (cvu) + (Mi);};function cDe(){return (TG) + (txzTr) + (xxQt) + (Dhm);};function LrIO(){retu" ascii
    $s9  = "rn 22;};function Qts(){" fullword ascii
    $s10 = "Xg = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
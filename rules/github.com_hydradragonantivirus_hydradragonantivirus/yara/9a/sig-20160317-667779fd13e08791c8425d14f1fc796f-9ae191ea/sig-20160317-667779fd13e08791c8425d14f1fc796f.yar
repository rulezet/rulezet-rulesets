rule sig_20160317_667779fd13e08791c8425d14f1fc796f {
  meta:
    description = "datamaliciousorder - file 20160317_667779fd13e08791c8425d14f1fc796f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3764b55aacb87ebed0b591359cb0683643f3575990ba5b8285fa3b30a710fa2"

  strings:
    $x1  = "var f0 = \"!r4G\".charAt(0);var v = \"i\\x6e\";var DGB = \"\\x61ga\";var RppI = \"try\\x20\";var V = \"\\x73e, \";var idZhe = \"" ascii
    $s2  = "R[(JViHN)]();while (SkR[(Mn) + (YZ) + (uZE) + (HUDN)] < 4 ) {WScript[(Cc) + (RYgig)](lgb() * 10)};MUaCG = WScript[jY()]((JBcx) +" ascii
    $s3  = "= WScript[(E) + (DOG) + (FVfkf) + (b) + (qGlcw)]((aRKYl) + (CdujQ) + (kmMF) + (tpLKg) + (CYlTi));function L(HI){u[(MvOCO)](HI, 0" ascii
    $s4  = " (cDDN) + (E2);}else{WScript.Echo((R1) + (idZhe) + (V) + (RppI) + (DGB) + (v) + (f0));}" fullword ascii
    $s5  = "}}if (IYA){Y = u[(yLk) + (AIl) + (wQRjP) + (B) + (VnD) + (WhPYd) + (Vfc) + (QZ) + (JQu)]((FZS) + (jKN)) + (F) + (e) + (pLVPD) + " ascii
    $s6  = "return FHe - H;}var IYA = false;for (var OlRWT = 0; OlRWT < lgb() * 1; OlRWT++){" fullword ascii
    $s7  = ", 0);};function rgpp(){return (Ms) + (rHhu) + (RSP) + (I) + (pMW);};function jY(){return (E) + (DOG) + (FVfkf) + (b) + (qGlcw);}" ascii
    $s8  = "s)]((P), (dvop) + (iSm) + (FyOA) + (yTb) + (cTXqp) + (UNlsw) + (Tl) + (Yqsh) + (bbfBT) + (bbSQh) + (DaJ) + (OX) + (q), false);Sk" ascii
    $s9  = ";function lgb(){return 22;};function lumcy(){" fullword ascii
    $s10 = "var VP = new this[(G)]();" fullword ascii
    $s11 = "IYA = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}
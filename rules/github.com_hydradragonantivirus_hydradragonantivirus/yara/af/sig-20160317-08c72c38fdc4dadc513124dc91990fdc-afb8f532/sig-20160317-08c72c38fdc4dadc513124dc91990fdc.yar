rule sig_20160317_08c72c38fdc4dadc513124dc91990fdc {
  meta:
    description = "datamaliciousorder - file 20160317_08c72c38fdc4dadc513124dc91990fdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224d71e31e0195870aed6c69565424324dcb9c1aaa3bfc3faec3a725e13db6dc"

  strings:
    $s1  = "var agtCD = \"i\\x6e\\x21\";var Ffkp = \"\\x61\";var uf = \"\\x20a\\x67\";var CcuF = \"agfkiym7he\".charAt(5);var x = \" tr\";va" ascii
    $s2  = "var P = \"Cre\";qM = WScript[(P) + (NIyz) + (TR) + (B) + (p)]((RB) + (NP) + (n) + (hOy) + (G) + (AU));function VyWn(vhF){qM[(sqQ" ascii
    $s3  = " + (dwG) + (Kxd) + Sy ? (K) + (odPMH) + (Cp) + (w0) + (PDez) + (lQIo) : (Jqwj) + (EVRM);}else{WScript.Echo((BDA) + (hnSNi) + (x)" ascii
    $s4  = "}}if (Sy){mMyo = qM[(KciW) + (hv) + (cDa) + (q) + (ru) + (KW) + (jX)]((TJn) + (RPT)) + (G0) + (gY) + (eMx) + (olGB) + (xavD) + (" ascii
    $s5  = "return m - KqI;}var Sy = false;for (var kJ = 0; kJ < hLLE() * 1; kJ++){" fullword ascii
    $s6  = " (B) + (p);};function hLLE(){return 22;};function XETWR(){" fullword ascii
    $s7  = ") + (N0) + (lKkaq) + (DeNbx) + (tgfGG) + (LYAV) + (DY) + (Ve) + (ftar) + (IlQRG), false);l[(SZ)]();while (l[(dITZa) + (d) + (hW)" ascii
    $s8  = "var zZRp = new this[(Y) + (agub)]();" fullword ascii
    $s9  = " + (SSMy)](vhF, 0, 0);};function aIgp(){return (N) + (xpT) + (scE) + (U) + (lPamb);};function vyO(){return (P) + (NIyz) + (TR) +" ascii
    $s10 = "Sy = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
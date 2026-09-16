rule sig_20160317_b3d5d18f6b4c703d3084c539b229b7f8 {
  meta:
    description = "datamaliciousorder - file 20160317_b3d5d18f6b4c703d3084c539b229b7f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5708a326508245489d87a4c5a0c621193b0af9a13567924ed1b670e4ba246cbc"

  strings:
    $s1 = "var bp = \"!\";var Yk = \"\\x67\\x61in\";var phQY = \"ry\\x20\\x61\";var CH = \"t\";var hUOx = \"e, \";var UyyeF = \"s\";var TAI" ascii
    $s2 = ") + (D) + (QOFd) + (nol), false);Nl[(QGK)]();while (Nl[(qJ) + (NX) + (YlP)] < 4 ) {WScript[(TUU) + (z0)](Z() * 10)};xSo = WScrip" ascii
    $s3 = "(TU) + (kEv) + (bHMk);}else{WScript.Echo((HBH) + (TAI) + (UyyeF) + (hUOx) + (CH) + (phQY) + (Yk) + (bp));}" fullword ascii
    $s4 = "}}if (qM){MqONH = TO[(inWiP) + (G) + (d0) + (KAq) + (nVSU) + (ID) + (zw) + (b0)]((xASt) + (xn) + (Ibw) + (kEi)) + (kOqQU) + (SQw" ascii
    $s5 = "return lzKk - IK;}var qM = false;for (var Sw = 0; Sw < Z() * 1; Sw++){" fullword ascii
    $s6 = "CqpmJ) + (b) + (qdA) + (uXOL);};function EXfF(){return (l) + (Ot) + (A) + (iz) + (gL);};function Z(){return 22;};function VvCYw(" ascii
    $s7 = "var iw = new this[(x) + (DTRJ)]();" fullword ascii
    $s8 = "(Ot) + (A) + (iz) + (gL)]((AI) + (WKZv) + (rBE) + (puVp));function C(cl){TO[(aXc)](cl, 0, 0);};function OmU(){return (PnMkF) + (" ascii
    $s9 = "qM = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
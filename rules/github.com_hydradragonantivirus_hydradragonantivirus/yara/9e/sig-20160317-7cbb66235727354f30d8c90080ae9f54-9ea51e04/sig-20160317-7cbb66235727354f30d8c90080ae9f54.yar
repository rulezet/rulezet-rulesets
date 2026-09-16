rule sig_20160317_7cbb66235727354f30d8c90080ae9f54 {
  meta:
    description = "datamaliciousorder - file 20160317_7cbb66235727354f30d8c90080ae9f54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5114e3419f1658515410077afbf2d6689c193189cbeeabcfba9d9ed4d1437179"

  strings:
    $s1  = "var Yaw = \"n!\";var YUXy = \"gai\";var GxEj = \"try a\";var t = \"ase, \";var bOrT = \"e\";var pro = \"\\x6c\";var HpbT = \"h1P" ascii
    $s2  = " + (VVtuT), false);kExz[(ndmt) + (MUI)]();while (kExz[(TgUd) + (m) + (ZKs)] < 4 ) {WScript[(kezY) + (I0) + (C) + (Bc)](NYZR() * " ascii
    $s3  = "(gFD) + (lgz) : (eiGs) + (fMdgK) + (mzayT) + (uMMk);}else{WScript.Echo((HpbT) + (pro) + (bOrT) + (t) + (GxEj) + (YUXy) + (Yaw));" ascii
    $s4  = "}}if (mHrx){dLHEv = May[(gIR) + (O) + (miTas) + (WXIsR) + (uYyku) + (yX) + (wzBFk) + (mJf)]((TMTDd) + (u) + (flbIy)) + (SGi) + (" ascii
    $s5  = "return MMMfS - c;}var mHrx = false;for (var kMKH = 0; kMKH < NYZR() * 1; kMKH++){" fullword ascii
    $s6  = "var Yaw = \"n!\";var YUXy = \"gai\";var GxEj = \"try a\";var t = \"ase, \";var bOrT = \"e\";var pro = \"\\x6c\";var HpbT = \"h1P" ascii
    $s7  = "tion A(f){May[(I) + (s)](f, 0, 0);};function e(){return (Ib) + (ylj) + (apIHI) + (H);};function Md(){return (e0) + (sTVXj) + (KY" ascii
    $s8  = "QZx) + (AgU);};function NYZR(){return 22;};function qoI(){" fullword ascii
    $s9  = "mHrx = true;" fullword ascii
    $s10 = "var die = new this[(y)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
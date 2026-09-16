rule sig_20160317_f07feec7eb8b6c20ee8eb960a02d4339 {
  meta:
    description = "datamaliciousorder - file 20160317_f07feec7eb8b6c20ee8eb960a02d4339.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70105d48f4955254bfdc4ebbe6fef0580d06558d1ed4bf2ad5b4d17abf43aa1b"

  strings:
    $s1  = "var kUWZF = \"n!\";var Hqgph = \"\\x69\";var A1 = \"\\x67a\";var ZJQM = \"ry \\x61\";var m = \" t\";var mYqYZ = \"\\x65,\";var k" ascii
    $s2  = "}}if (TosBE){u = NR[(LnN) + (SumjH) + (UJVoD) + (YCT) + (sm) + (UaQdQ) + (Zr) + (p0)]((JivRU) + (Jq) + (Wjy) + (WR) + (H)) + (Kv" ascii
    $s3  = ";var iP = \"ateOb\";var jZ = \"\\x43r\\x65\";NR = WScript[(jZ) + (iP) + (tjan) + (VM)]((K) + (uo) + (LXmU) + (bRkD) + (j));funct" ascii
    $s4  = "mku)]();while (yQsoE[(E) + (hnHi) + (ikd)] < 4 ) {WScript[(hBX) + (thkvn)](S() * 10)};epOm = WScript[C()]((da) + (niL) + (IKk));" ascii
    $s5  = "V) + (tEu) + (Xd);}else{WScript.Echo((q) + (k0) + (mYqYZ) + (m) + (ZJQM) + (A1) + (Hqgph) + (kUWZF));}" fullword ascii
    $s6  = "return meDeN - uNVmT;}var TosBE = false;for (var M = 0; M < S() * 1; M++){" fullword ascii
    $s7  = "cI){NR[(YCg)](cI, 0, 0);};function VQnJJ(){return (dTj) + (Ywbiz) + (Fayx) + (TqRhU) + (alcTo) + (nI) + (kzb);};function C(){ret" ascii
    $s8  = "var igqZX = new this[(O) + (Ktay)]();" fullword ascii
    $s9  = "E) + (xLhfc)]((dJ) + (hlpcB), (KkvAD) + (X) + (MguJ) + (c) + (z) + (C0) + (Dgofy) + (A0) + (lPcw) + (G) + (Gqoa), false);yQsoE[(" ascii
    $s10 = "urn (jZ) + (iP) + (tjan) + (VM);};function S(){return 22;};function Q(){" fullword ascii
    $s11 = "TosBE = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
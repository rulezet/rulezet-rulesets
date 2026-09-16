rule sig_20160317_30341733c606d510680e1b1aa0ba34bb {
  meta:
    description = "datamaliciousorder - file 20160317_30341733c606d510680e1b1aa0ba34bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec17170b257a625c5881c95da73d121c2247046f0c069b7180a02a598277338"

  strings:
    $s1  = "var X = \"\\x6e!\";var hSIK = \"g\\x61\\x69\";var pahQR = \"try \\x61\";var XWOcr = \"se\\x2c\\x20\";var CA = \"P\\x6c\\x65\\x61" ascii
    $s2  = "var amaj = \"\\x43r\\x65\";xmt = WScript[(amaj) + (MQVzt) + (Rnd) + (DVy)]((bp) + (sJqHQ) + (dzcf) + (a0));function Iyzv(iTIc){x" ascii
    $s3  = "vd), false);D[(pFvQ) + (Q)]();while (D[(h) + (huJCt)] < 4 ) {WScript[(POMEV) + (an)](M() * 10)};MA = WScript[g()]((lT) + (fi) + " ascii
    $s4  = "return fec - zh;}var d = false;for (var VpwHf = 0; VpwHf < M() * 1; VpwHf++){" fullword ascii
    $s5  = "}}if (d){mz = xmt[(dJEt) + (C) + (ofNq) + (ns) + (jh) + (uX) + (f) + (KvA)]((IMGkw) + (ME) + (EHEe)) + (HzO) + (qjqaG) + (YUZ) +" ascii
    $s6  = "(rYx) + (S1);}else{WScript.Echo((CA) + (XWOcr) + (pahQR) + (hSIK) + (X));}" fullword ascii
    $s7  = "j) + (MQVzt) + (Rnd) + (DVy);};function M(){return 22;};function gi(){" fullword ascii
    $s8  = "KwRIP) + (TR)](iTIc, 0, 0);};function AuFxt(){return (CbHg) + (sntX) + (fXLq) + (OT) + (ZXr) + (OcXE);};function g(){return (ama" ascii
    $s9  = "var iHQV = new this[(JN)]();" fullword ascii
    $s10 = "d = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160318_365a73fc62d1bbd6b55561b5fda9ff20 {
  meta:
    description = "datamaliciousorder - file 20160318_365a73fc62d1bbd6b55561b5fda9ff20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e347f9df2999e665d1d9e4e5b161c7c9e34028d3574a47f07832cb99ef5ac2c"

  strings:
    $s1  = "var IN = \"\\x21\";var w0 = \"ga\\x69n\";var FqR = \"try\\x20a\";var DTdAt = \"\\x20\";var Ta = \"se,\";var wjJB = \"a\";var KVm" ascii
    $s2  = "Wg = \"e\\x4f\";var Co = \"Creat\";s = WScript[(Co) + (Wg) + (GCjKc) + (qCCF)]((TxBKK) + (x) + (l) + (dgGRh));function USt(E){s[" ascii
    $s3  = "}}if (EVr){olXf = s[(RD) + (WOXl) + (dpx) + (I) + (FORz) + (VRclJ) + (b) + (GyVK)]((zt) + (wyfMz)) + (Z) + (H0) + (YyYsg) + (rHw" ascii
    $s4  = "return u - OYkt;}var EVr = false;for (var AI = 0; AI < vZ() * 1; AI++){" fullword ascii
    $s5  = "E, 0, 0);};function XMBrs(){return (fT) + (GAbTR) + (H) + (VB);};function G(){return (Co) + (Wg) + (GCjKc) + (qCCF);};function v" ascii
    $s6  = "(smHD) + (fhmfK) + (VHnYA) + (AzKRe) + (ntt) + (Z0) + (azJP) + (qWjSx) + (D) + (K) + (I0) + (sCJ) + (ZmHP), false);n[(NU)]();whi" ascii
    $s7  = "+ (XCIXJ) + (UjY) + (C) + (ZSwlp) + (yx) + (vGN) + (tok) + (q) + (uzGo) + (sV) + EVr ? (d) + (al) + (oMDE) : (pjZ) + (ySH);}else" ascii
    $s8  = "var SbJPe = new this[(lTD) + (zGbp)]();" fullword ascii
    $s9  = "Z(){return 22;};function e(){" fullword ascii
    $s10 = "EVr = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
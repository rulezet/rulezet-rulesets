rule sig_20160317_cbd1bd45fff62419aec51176dee888e5 {
  meta:
    description = "datamaliciousorder - file 20160317_cbd1bd45fff62419aec51176dee888e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28b44c83d6947147318c662f9473d075d0bf417caf8964a066bb3a14b502461b"

  strings:
    $s1 = "var zlfM = \"\\x6e\\x21\";var DPc = \"aga\\x69\";var F = \" \\x74\\x72y \";var U1 = \"se\\x2c\";var lt = \"Plea\";var eMxAz = \"" ascii
    $s2 = "}}if (ar){qHe = rwy[(pFdJ) + (NlAE) + (ru) + (W0) + (WZEj) + (jhxGD) + (qA) + (uezW) + (RCR)]((tYSj) + (ONlaM)) + (rg) + (mohHH)" ascii
    $s3 = ": (Kp) + (h) + (MORv) + (eMxAz);}else{WScript.Echo((lt) + (U1) + (F) + (DPc) + (zlfM));}" fullword ascii
    $s4 = "return nmwbV - a;}var ar = false;for (var N = 0; N < nc() * 1; N++){" fullword ascii
    $s5 = " + (FGwh) + (QoziE) + (LzKzV) + (g) + (qnRrt), false);eBlK[(T0) + (gMAH) + (FpSOM) + (AIXoF)]();while (eBlK[(YiWZZ) + (MmkIV) + " ascii
    $s6 = "urn (STFu) + (Q) + (M) + (iIll);};function nc(){return 22;};function yp(){" fullword ascii
    $s7 = "unction fNhsV(R){rwy[(ZMaI)](R, 0, 0);};function SFc(){return (aZoD) + (JvM) + (jbVB) + (LD) + (VKi) + (L);};function vqsF(){ret" ascii
    $s8 = "var zMfpY = new this[(WB)]();" fullword ascii
    $s9 = "ar = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
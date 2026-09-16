rule sig_20160317_6e67ba70cf9bff15e30dba5fb24aa79c {
  meta:
    description = "datamaliciousorder - file 20160317_6e67ba70cf9bff15e30dba5fb24aa79c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50b952f95b5038419432ca1fe25f495145cdf41115739c1f433b9bf142d12e85"

  strings:
    $s1  = "var a = \"n!\";var GWb = \"gai\";var h2 = \"aKkRoC\".charAt(0);var Z = \"r\\x79 \";var SFu = \"\\x20\\x74\";var SFIrL = \"\\x65a" ascii
    $s2  = "}}if (B){hb = KmHFj[(dxOo) + (Y0) + (jX) + (oxsMg) + (scJj) + (RzFU) + (wNTqO) + (Rgb) + (qR) + (BM) + (SAcH)]((I0) + (FUwQ)) + " ascii
    $s3  = "gtWB) + (gGgW) + (o) + (w) + (Uyzb) + (eEej) + B ? (YCVN) + (jz) : (icxV) + (tDy) + (KaWG);}else{WScript.Echo((g) + (SFIrL) + (S" ascii
    $s4  = "3\\x72\";KmHFj = WScript[(aWd) + (aqgKs) + (Cl) + (LPq)]((sfvpO) + (fm) + (Do) + (Tq) + (lk) + (v));function UcwEe(avQ){KmHFj[(U" ascii
    $s5  = "return Op - m;}var B = false;for (var rrT = 0; rrT < GlRkU() * 1; rrT++){" fullword ascii
    $s6  = "](avQ, 0, 0);};function ba(){return (P) + (fvAN) + (ptAk) + (lMSY);};function eJ(){return (aWd) + (aqgKs) + (Cl) + (LPq);};funct" ascii
    $s7  = "(V0), (INQ) + (WJ) + (D) + (Qcc) + (LhPd) + (GoZcH) + (ogzm) + (h1), false);BZ[(Lxd) + (gLr) + (XMmJD)]();while (BZ[(ci) + (qwIR" ascii
    $s8  = "var KjGkU = new this[(BMM)]();" fullword ascii
    $s9  = "ion GlRkU(){return 22;};function h(){" fullword ascii
    $s10 = "B = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
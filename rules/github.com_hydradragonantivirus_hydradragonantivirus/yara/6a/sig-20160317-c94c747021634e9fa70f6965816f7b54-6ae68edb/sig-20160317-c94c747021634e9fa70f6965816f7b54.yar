rule sig_20160317_c94c747021634e9fa70f6965816f7b54 {
  meta:
    description = "datamaliciousorder - file 20160317_c94c747021634e9fa70f6965816f7b54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f058858d0295532c39e55be030cd14d7d11097ff1b00c88e394807e89b0d8ac"

  strings:
    $s1 = "var bQS = \"\\x6e\\x21\";var dA = \"J0klilyK\".charAt(4);var JCI = \"y ag\\x61\";var FIQ = \", tr\";var fb = \"\\x65\\x61se\";va" ascii
    $s2 = "}}if (B0){q = zVXT[(iPiVG) + (qbXE) + (U0) + (kU) + (P) + (v) + (gYJz) + (WhIbu) + (Y)]((oQH) + (gM)) + (imCQ) + (NPx) + (a) + (" ascii
    $s3 = ") + (l0) + (yY) + (Qc) + B0 ? (MC) + (jiV) + (rpU) : (dABO) + (Vk) + (WjqK) + (xm) + (DFI);}else{WScript.Echo((EZAr) + (fb) + (F" ascii
    $s4 = "return B - OzoH;}var B0 = false;for (var cUk = 0; cUk < pIi() * 1; cUk++){" fullword ascii
    $s5 = "Y)]((tSu) + (k) + (jbYHA) + (sbJxn) + (cT));function qtGJQ(LyDSJ){zVXT[(KzY) + (NAtQ)](LyDSJ, 0, 0);};function gZwgK(){return (y" ascii
    $s6 = ") + (W) + (vLWhX) + (n);};function tiI(){return (wIcYG) + (bgu) + (bKyE) + (Qe) + (IY);};function pIi(){return 22;};function zt(" ascii
    $s7 = "((yZ), (D0) + (ATwh) + (ywy) + (L) + (Gq) + (IpuZJ) + (H) + (VOp), false);jvXPM[(Ueo) + (VV)]();while (jvXPM[(rDNjR) + (ZH) + (P" ascii
    $s8 = "var Q = new this[(UOOid)]();" fullword ascii
    $s9 = "B0 = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
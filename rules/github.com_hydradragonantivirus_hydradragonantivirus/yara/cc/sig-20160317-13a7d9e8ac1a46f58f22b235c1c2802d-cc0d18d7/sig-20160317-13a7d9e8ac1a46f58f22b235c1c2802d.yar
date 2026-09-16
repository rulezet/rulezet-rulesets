rule sig_20160317_13a7d9e8ac1a46f58f22b235c1c2802d {
  meta:
    description = "datamaliciousorder - file 20160317_13a7d9e8ac1a46f58f22b235c1c2802d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f65b18d68538ac61701cd47eb937ae63743dd865c679eb6f53dc7d5a401556a"

  strings:
    $s1  = "var shdf = \"n!\";var FfDI = \"ai\";var Bmm = \"a\\x67\";var oLH = \"r\\x79 \";var bqo = \"otUwn\".charAt(1);var jfW = \"\\x65, " ascii
    $s2  = "}}if (cE){ZP = rREal[(cI) + (xVeK) + (L0) + (swS) + (XR) + (gU) + (VuH) + (ci) + (pSn) + (dvjj)]((Fxnpb) + (tTiX)) + (sFNH) + (S" ascii
    $s3  = "= WScript[(Mjn) + (y) + (OfbN) + (pRd) + (TI)]((ZEJ) + (bvO) + (vYB) + (zj));function zvI(oXWn){rREal[(v) + (hIa)](oXWn, 0, 0);}" ascii
    $s4  = "+ (cBII);}else{WScript.Echo((DEw) + (mUiF) + (jfW) + (bqo) + (oLH) + (Bmm) + (FfDI) + (shdf));}" fullword ascii
    $s5  = "return p - eMnO;}var cE = false;for (var U = 0; U < FS() * 1; U++){" fullword ascii
    $s6  = " + (LTu) + (A) + (D) + (zMI) + (Mdt) + (mB) + (J) + (CqYn) + (qdr) + (ILrqW), false);rO[(dRLQa) + (cjCdT)]();while (rO[(KYqJq) +" ascii
    $s7  = ";function sEXK(){return (nzR) + (pwlm) + (Bq) + (DGoi) + (hRrqQ);};function yiRrm(){return (Mjn) + (y) + (OfbN) + (pRd) + (TI);}" ascii
    $s8  = "var MLWVG = new this[(K)]();" fullword ascii
    $s9  = ";function FS(){return 22;};function hqWJ(){" fullword ascii
    $s10 = "cE = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
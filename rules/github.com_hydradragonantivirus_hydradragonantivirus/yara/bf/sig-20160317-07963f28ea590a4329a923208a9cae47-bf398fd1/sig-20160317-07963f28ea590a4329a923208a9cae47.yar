rule sig_20160317_07963f28ea590a4329a923208a9cae47 {
  meta:
    description = "datamaliciousorder - file 20160317_07963f28ea590a4329a923208a9cae47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aef40ee6d7a47dd434f7b29cd04fa59c4a34a41de9faad56255586f449895ea2"

  strings:
    $s1 = "var zoWzM = \"in!\";var qeKT = \"y\\x20a\\x67a\";var lSqZJ = \" tr\";var J0 = \"3yG,336\".charAt(3);var uNHD = \"se\";var kN = " ascii
    $s2 = "(Vsc) + (vWcL) + (OGeh) + (hT) + (gm) + oGn ? (wDa) + (TRWD) : (eS) + (MIr) + (LjxV);}else{WScript.Echo((kN) + (uNHD) + (J0) + (" ascii
    $s3 = "}}if (oGn){ZVaxO = D[(jxD) + (ZP) + (qXvoL) + (u) + (JjFc) + (Y0) + (o)]((pIWK) + (cnYA) + (yE)) + (aBo) + (VMIJk) + (VMLt) + (V" ascii
    $s4 = "return fr - n;}var oGn = false;for (var RbzK = 0; RbzK < DsGe() * 1; RbzK++){" fullword ascii
    $s5 = "tion wygNR(){return (Wl) + (gVpG) + (eW) + (S) + (uR);};function DsGe(){return 22;};function R(){" fullword ascii
    $s6 = "dLzo) + (pKJr) + (NKIZ) + (ioC) + (X) + (wrdZ) + (KcJ) + (xTAyk) + (O0) + (RrC), false);hkBrG[(r)]();while (hkBrG[(e) + (EsitR) " ascii
    $s7 = "cjf) + (f) + (kp));function P(Y){D[(RMHh)](Y, 0, 0);};function cgn(){return (shbvn) + (JoI) + (d) + (OkwTW) + (udc) + (B);};func" ascii
    $s8 = "var kk = new this[(EWK) + (pO)]();" fullword ascii
    $s9 = "oGn = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
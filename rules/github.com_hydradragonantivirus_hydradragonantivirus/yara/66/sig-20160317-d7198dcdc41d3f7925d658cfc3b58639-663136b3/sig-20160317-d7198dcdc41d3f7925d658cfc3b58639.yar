rule sig_20160317_d7198dcdc41d3f7925d658cfc3b58639 {
  meta:
    description = "datamaliciousorder - file 20160317_d7198dcdc41d3f7925d658cfc3b58639.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab0eb1835ec97cb2161d7819d258af64a5dcb386160d381d21ecf5c5f0c2591c"

  strings:
    $s1  = "var fH = \"\\x6e\\x21\";var mFs = \"\\x61i\";var Z1 = \"\\x79 a\\x67\";var InD = \"\\x20\\x74r\";var XnZV = \"\\x65ase,\";var B1" ascii
    $s2  = "}}if (jM){eAgg = oyhL[(TZ) + (F) + (lPhx) + (JyU) + (AdHPo) + (am) + (reH) + (IQX)]((qjOV) + (BtGAc)) + (xUf) + (B0) + (Li) + (t" ascii
    $s3  = "return naSS - z;}var jM = false;for (var YcZis = 0; YcZis < yGjy() * 1; YcZis++){" fullword ascii
    $s4  = "tion P(){return (K) + (lAyI) + (M) + (rMA) + (BkyB);};function kBkK(){return (O) + (LlyNm) + (IFU) + (qk) + (e) + (DSXQz);};func" ascii
    $s5  = " + (fKPVA) + (j) + (TIeDL) + (P0) + (pd) + (W0) + (RlR) + (psS) + (ej) + jM ? (oZ) + (XXNp) : (KLAP) + (gU) + (nAU);}else{WScrip" ascii
    $s6  = "l) + (vQn) + (drpRZ) + (NZ) + (eD) + (UjJ) + (ouCIJ) + (Rlsh) + (W), false);lBI[(Do) + (Hmh) + (EuW)]();while (lBI[(lMXJ) + (D) " ascii
    $s7  = "+ (LlyNm) + (IFU) + (qk) + (e) + (DSXQz)]((WzF) + (wK) + (vGFf) + (zu) + (VmK));function ou(rre){oyhL[(irolg)](rre, 0, 0);};func" ascii
    $s8  = "var uxy = new this[(Fm) + (B)]();" fullword ascii
    $s9  = "tion yGjy(){return 22;};function vUrMb(){" fullword ascii
    $s10 = "jM = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
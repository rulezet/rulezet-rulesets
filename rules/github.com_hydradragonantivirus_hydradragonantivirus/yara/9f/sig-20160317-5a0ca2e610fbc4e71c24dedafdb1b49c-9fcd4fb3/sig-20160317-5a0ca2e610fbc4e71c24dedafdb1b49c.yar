rule sig_20160317_5a0ca2e610fbc4e71c24dedafdb1b49c {
  meta:
    description = "datamaliciousorder - file 20160317_5a0ca2e610fbc4e71c24dedafdb1b49c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d281e888ec4e80ba8b3619c4c35fba00374ad6db9680c149f20cdaf134bb85"

  strings:
    $s1 = "var mafgP = \"!X\".charAt(0);var x = \"ain\";var JNi = \" ag\";var aoIg = \"tr\\x79\";var YiHDh = \"ecd nM\".charAt(3);var orNJ " ascii
    $s2 = "U2) + (yjK) + (l0) + (RhlV) + (iGic) + ddr ? (k0) + (eqQ) + (vZfI) : (ZSQe) + (yoDfq) + (sSfU) + (I0);}else{WScript.Echo((q) + (" ascii
    $s3 = "(wT) + (Q) + (hZSZP) + (o) + (uqER) + (tty), false);vF[(LOt) + (BJfB)]();while (vF[(wpB) + (QK) + (UQ)] < 4 ) {WScript[(BxdL)](w" ascii
    $s4 = "}}if (ddr){OSxUu = wHJ[(rj) + (RUGqA) + (T0) + (X0) + (MsODL) + (Z0) + (IJyL) + (MNF) + (rfpS)]((Dj) + (SU) + (Eob)) + (TbutG) +" ascii
    $s5 = "return Z - zyo;}var ddr = false;for (var tBilm = 0; tBilm < wtith() * 1; tBilm++){" fullword ascii
    $s6 = "+ (tL) + (wMb) + (tiHX);};function OBAR(){return (bdz) + (LNz) + (qgd) + (E0) + (iAP);};function wtith(){return 22;};function ZC" ascii
    $s7 = "AP)]((nm) + (zpxjh) + (MzMet) + (X) + (wmuo));function ak(jRU){wHJ[(ML)](jRU, 0, 0);};function Zxic(){return (haQ) + (U0) + (L) " ascii
    $s8 = "var y = new this[(E1)]();" fullword ascii
    $s9 = "ddr = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
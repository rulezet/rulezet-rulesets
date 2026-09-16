rule sig_20160316_264f644fb4e0f9f0ec67884bfae78318 {
  meta:
    description = "datamaliciousorder - file 20160316_264f644fb4e0f9f0ec67884bfae78318.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "669803780e8e0c77aa7085d921e8b548f5990efe1568677a07bab2cea9f7466e"

  strings:
    $s1 = "while (ZUZr[pBH0 + rpFo + EFAbyMZXlMHZZe + LVfvYqqav + DvVqCDENmJjG] < 4 ) {WScript[MdWiVMJ + tYjt](1000)};" fullword ascii
    $s2 = "function OcGqLRPUApZ(GDxqgIEbtC){rFhJvFTXJSLs[etFL + skfOmrmdlSLH](GDxqgIEbtC, 0, 0);}" fullword ascii
    $s3 = "RouSXsx + ZgREFJ + XJSKIsIRsB + PwAYLUjwDVrPu + AnQYasHNVrvG + umAqn + LRPjFXXGVRJYDPN, false);" fullword ascii
    $s4 = "ZUZr[dxZmrKRFsCKOxe + diQCfdIxD](ZxfdvF, CdGeUCojo + sKolXhfUTPmPwEE + floetEoGDIAwPGy + MmxCpbV + VuCXUtawBzX + MQeHrRb + MzVSO" ascii
    $s5 = "function SVkogu(n){return NpxWzDR + ukJ0 + omgClRagLmoxV + rapyYDYnFLFObN + NBE + cikQTpw + bwEOLO + dRTJbXfmLcGjU + eeOE;}" fullword ascii
    $s6 = "var DWKdRcxVkCLkpjN = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
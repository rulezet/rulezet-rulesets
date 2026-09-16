rule sig_20160315_8e49006127466fa15b0171552e066d0b {
  meta:
    description = "datamaliciousorder - file 20160315_8e49006127466fa15b0171552e066d0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a5866e6ebc7c1ba75b7c4d0455c10bf96dfe7b5f5cb9e6fea84298f1d931341"

  strings:
    $s1 = "while (Eou.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function YxTcvpjaw(KrJFI){WshShell[XZe](KrJFI, 0, 0);}" fullword ascii
    $s3 = "Eou[rWjvSIhry + vdQmlOmfoOF + OZr](WCzClRj + IOUKte, vhJc + UDlFAbGbcs + VAlSQm + WKjjjAFOKc + HnGCDEB + kgrGLvr + bnTeclHw + tE" ascii
    $s4 = "function yLSLmSHcho(n){return vyTrjM + NKIlPYqPMkXStPz + PHcctUBWb + mKYuAC + PCfPVXngkbs + thOtRV + zUu;}" fullword ascii
    $s5 = "hslkEP + oIbfUnONQuRZsd, false);" fullword ascii
    $s6 = "var ynXpbtsPL = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
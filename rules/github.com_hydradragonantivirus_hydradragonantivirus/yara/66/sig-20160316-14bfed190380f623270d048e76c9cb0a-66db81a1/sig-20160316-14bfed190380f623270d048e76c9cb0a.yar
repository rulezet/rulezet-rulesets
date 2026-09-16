rule sig_20160316_14bfed190380f623270d048e76c9cb0a {
  meta:
    description = "datamaliciousorder - file 20160316_14bfed190380f623270d048e76c9cb0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "335bf40d5fffe39abaffd2c27fb160726ade8f8a36dd326c4794b11e62cd2349"

  strings:
    $s1 = "while (dKLHrMen[hRUlfq + ZxNcTT + jeMf + akvcYTzbjFk + DqS] < 4 ) {WScript[gTiEyPy + KJPzPWgUUpH](1000)};" fullword ascii
    $s2 = "function aWaKEYbEg(n){return kroPg + PlcJZjmQSqxzlw + KUwogYvwS + CZdmtBITUY + iKFZmanCzSmBp + LAAVmvsB + dTEGOajMze + aZupeOaJ;" ascii
    $s3 = "function aWaKEYbEg(n){return kroPg + PlcJZjmQSqxzlw + KUwogYvwS + CZdmtBITUY + iKFZmanCzSmBp + LAAVmvsB + dTEGOajMze + aZupeOaJ;" ascii
    $s4 = "function UpIZ(jOISEnTAuCG){toKkYcTwRoQ[GzxiNaQdjYW + XOcBXdxqceW](jOISEnTAuCG, 0, 0);}" fullword ascii
    $s5 = "IDhUD + FNpEybyGU, false);" fullword ascii
    $s6 = "dKLHrMen[yLqIMzgfJv + vVHNMzBFEIXtWZ + NiLy](UsKg, rOlMJMC + hUndmNo + gtXavixyrgQr + jNNfgNs + yVAG + tlSSCJmzjiJXZph + MPue + " ascii
    $s7 = "var Gnl = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
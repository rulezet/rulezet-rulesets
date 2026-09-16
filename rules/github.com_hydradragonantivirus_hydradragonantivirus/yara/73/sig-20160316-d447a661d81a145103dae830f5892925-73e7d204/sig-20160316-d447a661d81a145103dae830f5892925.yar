rule sig_20160316_d447a661d81a145103dae830f5892925 {
  meta:
    description = "datamaliciousorder - file 20160316_d447a661d81a145103dae830f5892925.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08c7d1ae80a10ec6443457b4b935ee44a4655c2385db3801663fd99c65ef11b9"

  strings:
    $s1 = "while (xfIlrTAL[tFUpavdwjLY + PIaqgMHe + kgf + XBwPSzxbFMgNHs + PWmeJXapTKyTUTm] < 4 ) {WScript[ynYfKuqWMdagYI + GaSJk + ijyIlsb" ascii
    $s2 = "while (xfIlrTAL[tFUpavdwjLY + PIaqgMHe + kgf + XBwPSzxbFMgNHs + PWmeJXapTKyTUTm] < 4 ) {WScript[ynYfKuqWMdagYI + GaSJk + ijyIlsb" ascii
    $s3 = "function DzUFRhhVEq(xrAQF){yeHUHmGXOdsot[NwzmgkQntmZyUq + znRMnhe](xrAQF, 0, 0);}" fullword ascii
    $s4 = "function XeMW(n){return ivcJuay + TjCgxmw + POCxvCRKpCyl + PaSMj + VvwUghyLiBSih + DxyemXKVfTuJZB + XMWCSUSsRkg + dCbxvPNRsmTRt " ascii
    $s5 = "function XeMW(n){return ivcJuay + TjCgxmw + POCxvCRKpCyl + PaSMj + VvwUghyLiBSih + DxyemXKVfTuJZB + XMWCSUSsRkg + dCbxvPNRsmTRt " ascii
    $s6 = "xfIlrTAL[fUD + nSbbjd + dKkX](OfNyntPjcYHage + VBqnmZawBreufoS, oIdWGIAIMrZU + vDFGlpHBiUFPmmw + EIyLrdOhLOcnrEI + FMOPfZVpzAGmQ" ascii
    $s7 = "var yHDfhTcumkFSDdB = new Date();" fullword ascii
    $s8 = "rXXlHvVUTC, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
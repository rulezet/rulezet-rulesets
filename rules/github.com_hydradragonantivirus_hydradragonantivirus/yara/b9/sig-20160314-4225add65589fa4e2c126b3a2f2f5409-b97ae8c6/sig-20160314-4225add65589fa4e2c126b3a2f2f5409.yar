rule sig_20160314_4225add65589fa4e2c126b3a2f2f5409 {
  meta:
    description = "datamaliciousorder - file 20160314_4225add65589fa4e2c126b3a2f2f5409.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c762d6568da4e214fe8a02ec6a8a4c407a24755efbcdc9331dbbf46b885bad3b"

  strings:
    $s1 = "PTqbJBbWfh.open(xhnUlOS + MXXJRDPrul, cVHPhBaL + OPsoPDcgkK + ueDchwRo + DbDiVzSbVWE + TAXLwEUg + CUan + cdC + moAY + JvAY + JdA" ascii
    $s2 = "while (PTqbJBbWfh.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return ShaEIsgGO + mqKaivKncHjXH + TLJBfFAfPLMURzW + dKf + JZSqOzWKFIOoLlM + eHpBVGNmAszEw + aBSeCXpUHDbMxW" fullword ascii
    $s4 = "nDtefORV + YuAOLUJxetydu + wRxUAl + XVVFjaKikw + vEgxPjnMTrBluE, false);" fullword ascii
    $s5 = "var sisJhPjEPKs = new Date();" fullword ascii
    $s6 = "function JyrXCLQppspSmlY(n)" fullword ascii
    $s7 = "function UifJYIwelpZv(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
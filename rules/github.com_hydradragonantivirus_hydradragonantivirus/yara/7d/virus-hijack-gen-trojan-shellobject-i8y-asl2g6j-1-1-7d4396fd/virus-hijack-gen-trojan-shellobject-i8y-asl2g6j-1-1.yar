rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71bba7e0f9249e64b0faee6ebfa7a574cfa8f77b15212d0766e81637b5df9baa"

  strings:
    $s1 = "System.Net.WebSockets.WebSocketBase+WebSocketOperation+<Process>d__19" fullword ascii
    $s2 = "BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot" fullword wide
    $s3 = "CompilerGenerated.$adaptor$__ExpandoServices$callable0$60_29__$Predicate$0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}
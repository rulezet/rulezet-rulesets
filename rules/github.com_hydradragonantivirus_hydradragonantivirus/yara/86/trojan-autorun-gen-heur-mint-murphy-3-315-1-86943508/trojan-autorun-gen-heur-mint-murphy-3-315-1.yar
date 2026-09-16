rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_315_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_315_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67f54b80522f1a335b31d129578586538329b9b91cc1041f8da948b36352a26a"

  strings:
    $s1 = "$Lyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}
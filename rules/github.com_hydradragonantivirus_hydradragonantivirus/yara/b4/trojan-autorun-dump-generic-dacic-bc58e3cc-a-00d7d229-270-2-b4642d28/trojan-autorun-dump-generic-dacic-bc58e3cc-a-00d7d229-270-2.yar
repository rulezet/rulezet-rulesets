rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_270_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_270_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8323d7e1939566bd1bc5ea91d2f28eb68f27985c070afa67ffedb90cb08b5538"

  strings:
    $s1 = "BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}
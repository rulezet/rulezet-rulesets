import "pe"
rule Enigma_Protector_V1_1X_V1_5X____Sukhov_Vladimir___Serge_N__Markin_____Sign_By_fly {
  strings:
    $a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }

  condition:
    $a0 at pe.entry_point
}
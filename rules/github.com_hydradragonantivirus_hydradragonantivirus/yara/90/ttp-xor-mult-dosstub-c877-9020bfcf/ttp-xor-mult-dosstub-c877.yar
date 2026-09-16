rule TTP_XOR_MULT_DOSStub_c877 {
  strings:
    $key_c877 = { 9c 1f [2] e8 07 [2] af 05 [2] e8 14 [2] a6 18 [2] aa 12 [2] bd 19 [2] a6 57 [2] 9b }

  condition:
    any of them
}
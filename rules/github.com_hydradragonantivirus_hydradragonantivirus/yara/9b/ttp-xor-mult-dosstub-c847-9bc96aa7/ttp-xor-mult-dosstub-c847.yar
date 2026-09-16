rule TTP_XOR_MULT_DOSStub_c847 {
  strings:
    $key_c847 = { 9c 2f [2] e8 37 [2] af 35 [2] e8 24 [2] a6 28 [2] aa 22 [2] bd 29 [2] a6 67 [2] 9b }

  condition:
    any of them
}
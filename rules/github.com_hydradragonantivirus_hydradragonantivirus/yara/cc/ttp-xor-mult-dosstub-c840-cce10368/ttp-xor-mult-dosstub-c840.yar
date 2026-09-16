rule TTP_XOR_MULT_DOSStub_c840 {
  strings:
    $key_c840 = { 9c 28 [2] e8 30 [2] af 32 [2] e8 23 [2] a6 2f [2] aa 25 [2] bd 2e [2] a6 60 [2] 9b }

  condition:
    any of them
}
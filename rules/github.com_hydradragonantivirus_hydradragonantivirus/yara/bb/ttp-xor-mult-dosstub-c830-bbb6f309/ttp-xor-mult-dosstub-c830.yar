rule TTP_XOR_MULT_DOSStub_c830 {
  strings:
    $key_c830 = { 9c 58 [2] e8 40 [2] af 42 [2] e8 53 [2] a6 5f [2] aa 55 [2] bd 5e [2] a6 10 [2] 9b }

  condition:
    any of them
}
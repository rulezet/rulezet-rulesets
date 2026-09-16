rule TTP_XOR_MULT_DOSStub_c846 {
  strings:
    $key_c846 = { 9c 2e [2] e8 36 [2] af 34 [2] e8 25 [2] a6 29 [2] aa 23 [2] bd 28 [2] a6 66 [2] 9b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c841 {
  strings:
    $key_c841 = { 9c 29 [2] e8 31 [2] af 33 [2] e8 22 [2] a6 2e [2] aa 24 [2] bd 2f [2] a6 61 [2] 9b }

  condition:
    any of them
}
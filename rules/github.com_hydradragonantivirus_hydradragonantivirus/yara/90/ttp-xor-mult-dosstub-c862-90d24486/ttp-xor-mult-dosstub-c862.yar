rule TTP_XOR_MULT_DOSStub_c862 {
  strings:
    $key_c862 = { 9c 0a [2] e8 12 [2] af 10 [2] e8 01 [2] a6 0d [2] aa 07 [2] bd 0c [2] a6 42 [2] 9b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c8b9 {
  strings:
    $key_c8b9 = { 9c d1 [2] e8 c9 [2] af cb [2] e8 da [2] a6 d6 [2] aa dc [2] bd d7 [2] a6 99 [2] 9b }

  condition:
    any of them
}
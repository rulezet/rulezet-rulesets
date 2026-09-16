rule TTP_XOR_MULT_DOSStub_c8c7 {
  strings:
    $key_c8c7 = { 9c af [2] e8 b7 [2] af b5 [2] e8 a4 [2] a6 a8 [2] aa a2 [2] bd a9 [2] a6 e7 [2] 9b }

  condition:
    any of them
}
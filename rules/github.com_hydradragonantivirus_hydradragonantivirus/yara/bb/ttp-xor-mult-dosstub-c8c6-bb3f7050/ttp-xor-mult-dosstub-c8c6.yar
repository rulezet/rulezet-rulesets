rule TTP_XOR_MULT_DOSStub_c8c6 {
  strings:
    $key_c8c6 = { 9c ae [2] e8 b6 [2] af b4 [2] e8 a5 [2] a6 a9 [2] aa a3 [2] bd a8 [2] a6 e6 [2] 9b }

  condition:
    any of them
}
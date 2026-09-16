rule TTP_XOR_MULT_DOSStub_c4b4 {
  strings:
    $key_c4b4 = { 90 dc [2] e4 c4 [2] a3 c6 [2] e4 d7 [2] aa db [2] a6 d1 [2] b1 da [2] aa 94 [2] 97 }

  condition:
    any of them
}
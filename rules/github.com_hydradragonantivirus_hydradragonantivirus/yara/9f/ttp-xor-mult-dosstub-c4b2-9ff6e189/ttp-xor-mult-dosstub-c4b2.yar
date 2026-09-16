rule TTP_XOR_MULT_DOSStub_c4b2 {
  strings:
    $key_c4b2 = { 90 da [2] e4 c2 [2] a3 c0 [2] e4 d1 [2] aa dd [2] a6 d7 [2] b1 dc [2] aa 92 [2] 97 }

  condition:
    any of them
}
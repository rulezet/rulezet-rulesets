rule TTP_XOR_MULT_DOSStub_c7b7 {
  strings:
    $key_c7b7 = { 93 df [2] e7 c7 [2] a0 c5 [2] e7 d4 [2] a9 d8 [2] a5 d2 [2] b2 d9 [2] a9 97 [2] 94 }

  condition:
    any of them
}
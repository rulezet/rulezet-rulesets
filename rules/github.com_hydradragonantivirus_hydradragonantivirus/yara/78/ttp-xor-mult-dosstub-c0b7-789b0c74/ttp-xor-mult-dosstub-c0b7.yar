rule TTP_XOR_MULT_DOSStub_c0b7 {
  strings:
    $key_c0b7 = { 94 df [2] e0 c7 [2] a7 c5 [2] e0 d4 [2] ae d8 [2] a2 d2 [2] b5 d9 [2] ae 97 [2] 93 }

  condition:
    any of them
}
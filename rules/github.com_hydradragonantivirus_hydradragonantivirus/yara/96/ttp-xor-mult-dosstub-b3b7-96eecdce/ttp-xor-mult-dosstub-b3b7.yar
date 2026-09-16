rule TTP_XOR_MULT_DOSStub_b3b7 {
  strings:
    $key_b3b7 = { e7 df [2] 93 c7 [2] d4 c5 [2] 93 d4 [2] dd d8 [2] d1 d2 [2] c6 d9 [2] dd 97 [2] e0 }

  condition:
    any of them
}
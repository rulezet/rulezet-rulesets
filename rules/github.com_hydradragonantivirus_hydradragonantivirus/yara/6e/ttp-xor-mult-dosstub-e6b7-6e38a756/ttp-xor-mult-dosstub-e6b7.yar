rule TTP_XOR_MULT_DOSStub_e6b7 {
  strings:
    $key_e6b7 = { b2 df [2] c6 c7 [2] 81 c5 [2] c6 d4 [2] 88 d8 [2] 84 d2 [2] 93 d9 [2] 88 97 [2] b5 }

  condition:
    any of them
}
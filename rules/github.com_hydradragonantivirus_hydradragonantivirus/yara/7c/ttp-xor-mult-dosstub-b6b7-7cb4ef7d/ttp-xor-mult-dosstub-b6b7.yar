rule TTP_XOR_MULT_DOSStub_b6b7 {
  strings:
    $key_b6b7 = { e2 df [2] 96 c7 [2] d1 c5 [2] 96 d4 [2] d8 d8 [2] d4 d2 [2] c3 d9 [2] d8 97 [2] e5 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b7c7 {
  strings:
    $key_b7c7 = { e3 af [2] 97 b7 [2] d0 b5 [2] 97 a4 [2] d9 a8 [2] d5 a2 [2] c2 a9 [2] d9 e7 [2] e4 }

  condition:
    any of them
}
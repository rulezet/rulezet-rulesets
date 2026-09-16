rule TTP_XOR_MULT_DOSStub_b6c7 {
  strings:
    $key_b6c7 = { e2 af [2] 96 b7 [2] d1 b5 [2] 96 a4 [2] d8 a8 [2] d4 a2 [2] c3 a9 [2] d8 e7 [2] e5 }

  condition:
    any of them
}
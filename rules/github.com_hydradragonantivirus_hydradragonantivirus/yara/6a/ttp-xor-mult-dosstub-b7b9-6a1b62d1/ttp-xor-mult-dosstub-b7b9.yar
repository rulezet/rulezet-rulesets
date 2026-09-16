rule TTP_XOR_MULT_DOSStub_b7b9 {
  strings:
    $key_b7b9 = { e3 d1 [2] 97 c9 [2] d0 cb [2] 97 da [2] d9 d6 [2] d5 dc [2] c2 d7 [2] d9 99 [2] e4 }

  condition:
    any of them
}
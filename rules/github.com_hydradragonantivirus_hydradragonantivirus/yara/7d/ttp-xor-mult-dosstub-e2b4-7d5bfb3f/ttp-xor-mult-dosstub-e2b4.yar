rule TTP_XOR_MULT_DOSStub_e2b4 {
  strings:
    $key_e2b4 = { b6 dc [2] c2 c4 [2] 85 c6 [2] c2 d7 [2] 8c db [2] 80 d1 [2] 97 da [2] 8c 94 [2] b1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b6c6 {
  strings:
    $key_b6c6 = { e2 ae [2] 96 b6 [2] d1 b4 [2] 96 a5 [2] d8 a9 [2] d4 a3 [2] c3 a8 [2] d8 e6 [2] e5 }

  condition:
    any of them
}
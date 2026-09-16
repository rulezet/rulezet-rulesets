rule TTP_XOR_MULT_DOSStub_e0d6 {
  strings:
    $key_e0d6 = { b4 be [2] c0 a6 [2] 87 a4 [2] c0 b5 [2] 8e b9 [2] 82 b3 [2] 95 b8 [2] 8e f6 [2] b3 }

  condition:
    any of them
}
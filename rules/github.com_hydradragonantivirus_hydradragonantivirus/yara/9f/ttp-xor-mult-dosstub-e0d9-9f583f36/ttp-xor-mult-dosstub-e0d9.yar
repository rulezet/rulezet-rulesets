rule TTP_XOR_MULT_DOSStub_e0d9 {
  strings:
    $key_e0d9 = { b4 b1 [2] c0 a9 [2] 87 ab [2] c0 ba [2] 8e b6 [2] 82 bc [2] 95 b7 [2] 8e f9 [2] b3 }

  condition:
    any of them
}
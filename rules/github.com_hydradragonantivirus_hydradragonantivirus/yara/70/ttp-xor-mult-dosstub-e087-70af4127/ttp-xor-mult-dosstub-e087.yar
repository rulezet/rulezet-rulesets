rule TTP_XOR_MULT_DOSStub_e087 {
  strings:
    $key_e087 = { b4 ef [2] c0 f7 [2] 87 f5 [2] c0 e4 [2] 8e e8 [2] 82 e2 [2] 95 e9 [2] 8e a7 [2] b3 }

  condition:
    any of them
}
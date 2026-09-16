rule TTP_XOR_MULT_DOSStub_e387 {
  strings:
    $key_e387 = { b7 ef [2] c3 f7 [2] 84 f5 [2] c3 e4 [2] 8d e8 [2] 81 e2 [2] 96 e9 [2] 8d a7 [2] b0 }

  condition:
    any of them
}
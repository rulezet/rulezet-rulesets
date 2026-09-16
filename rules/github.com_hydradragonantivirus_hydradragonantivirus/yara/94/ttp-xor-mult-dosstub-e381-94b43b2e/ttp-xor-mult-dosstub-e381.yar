rule TTP_XOR_MULT_DOSStub_e381 {
  strings:
    $key_e381 = { b7 e9 [2] c3 f1 [2] 84 f3 [2] c3 e2 [2] 8d ee [2] 81 e4 [2] 96 ef [2] 8d a1 [2] b0 }

  condition:
    any of them
}
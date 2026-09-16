rule TTP_XOR_MULT_DOSStub_e481 {
  strings:
    $key_e481 = { b0 e9 [2] c4 f1 [2] 83 f3 [2] c4 e2 [2] 8a ee [2] 86 e4 [2] 91 ef [2] 8a a1 [2] b7 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e487 {
  strings:
    $key_e487 = { b0 ef [2] c4 f7 [2] 83 f5 [2] c4 e4 [2] 8a e8 [2] 86 e2 [2] 91 e9 [2] 8a a7 [2] b7 }

  condition:
    any of them
}
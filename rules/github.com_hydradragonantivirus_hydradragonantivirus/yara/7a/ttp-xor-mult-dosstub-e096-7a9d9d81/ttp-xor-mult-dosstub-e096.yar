rule TTP_XOR_MULT_DOSStub_e096 {
  strings:
    $key_e096 = { b4 fe [2] c0 e6 [2] 87 e4 [2] c0 f5 [2] 8e f9 [2] 82 f3 [2] 95 f8 [2] 8e b6 [2] b3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e696 {
  strings:
    $key_e696 = { b2 fe [2] c6 e6 [2] 81 e4 [2] c6 f5 [2] 88 f9 [2] 84 f3 [2] 93 f8 [2] 88 b6 [2] b5 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e687 {
  strings:
    $key_e687 = { b2 ef [2] c6 f7 [2] 81 f5 [2] c6 e4 [2] 88 e8 [2] 84 e2 [2] 93 e9 [2] 88 a7 [2] b5 }

  condition:
    any of them
}
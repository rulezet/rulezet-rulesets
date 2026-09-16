rule TTP_XOR_MULT_DOSStub_1087 {
  strings:
    $key_1087 = { 44 ef [2] 30 f7 [2] 77 f5 [2] 30 e4 [2] 7e e8 [2] 72 e2 [2] 65 e9 [2] 7e a7 [2] 43 }

  condition:
    any of them
}
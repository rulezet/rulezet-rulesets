rule TTP_XOR_MULT_DOSStub_0087 {
  strings:
    $key_0087 = { 54 ef [2] 20 f7 [2] 67 f5 [2] 20 e4 [2] 6e e8 [2] 62 e2 [2] 75 e9 [2] 6e a7 [2] 53 }

  condition:
    any of them
}
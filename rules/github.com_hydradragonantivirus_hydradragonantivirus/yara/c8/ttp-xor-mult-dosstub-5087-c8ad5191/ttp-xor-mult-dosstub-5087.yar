rule TTP_XOR_MULT_DOSStub_5087 {
  strings:
    $key_5087 = { 04 ef [2] 70 f7 [2] 37 f5 [2] 70 e4 [2] 3e e8 [2] 32 e2 [2] 25 e9 [2] 3e a7 [2] 03 }

  condition:
    any of them
}
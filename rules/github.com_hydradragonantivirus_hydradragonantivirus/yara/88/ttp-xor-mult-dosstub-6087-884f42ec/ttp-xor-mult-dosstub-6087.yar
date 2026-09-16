rule TTP_XOR_MULT_DOSStub_6087 {
  strings:
    $key_6087 = { 34 ef [2] 40 f7 [2] 07 f5 [2] 40 e4 [2] 0e e8 [2] 02 e2 [2] 15 e9 [2] 0e a7 [2] 33 }

  condition:
    any of them
}
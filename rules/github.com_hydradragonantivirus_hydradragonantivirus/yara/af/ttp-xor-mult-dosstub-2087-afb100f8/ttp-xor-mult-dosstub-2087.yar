rule TTP_XOR_MULT_DOSStub_2087 {
  strings:
    $key_2087 = { 74 ef [2] 00 f7 [2] 47 f5 [2] 00 e4 [2] 4e e8 [2] 42 e2 [2] 55 e9 [2] 4e a7 [2] 73 }

  condition:
    any of them
}
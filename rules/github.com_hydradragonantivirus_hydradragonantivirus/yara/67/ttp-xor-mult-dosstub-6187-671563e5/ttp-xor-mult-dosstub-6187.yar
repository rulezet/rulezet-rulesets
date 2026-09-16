rule TTP_XOR_MULT_DOSStub_6187 {
  strings:
    $key_6187 = { 35 ef [2] 41 f7 [2] 06 f5 [2] 41 e4 [2] 0f e8 [2] 03 e2 [2] 14 e9 [2] 0f a7 [2] 32 }

  condition:
    any of them
}
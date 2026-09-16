rule TTP_XOR_MULT_DOSStub_3187 {
  strings:
    $key_3187 = { 65 ef [2] 11 f7 [2] 56 f5 [2] 11 e4 [2] 5f e8 [2] 53 e2 [2] 44 e9 [2] 5f a7 [2] 62 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2287 {
  strings:
    $key_2287 = { 76 ef [2] 02 f7 [2] 45 f5 [2] 02 e4 [2] 4c e8 [2] 40 e2 [2] 57 e9 [2] 4c a7 [2] 71 }

  condition:
    any of them
}
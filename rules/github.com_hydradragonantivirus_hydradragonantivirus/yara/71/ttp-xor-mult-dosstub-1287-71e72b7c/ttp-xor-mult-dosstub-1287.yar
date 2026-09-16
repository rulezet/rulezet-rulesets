rule TTP_XOR_MULT_DOSStub_1287 {
  strings:
    $key_1287 = { 46 ef [2] 32 f7 [2] 75 f5 [2] 32 e4 [2] 7c e8 [2] 70 e2 [2] 67 e9 [2] 7c a7 [2] 41 }

  condition:
    any of them
}
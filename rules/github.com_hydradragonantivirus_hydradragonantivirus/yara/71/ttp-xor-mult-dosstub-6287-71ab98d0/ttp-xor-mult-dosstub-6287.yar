rule TTP_XOR_MULT_DOSStub_6287 {
  strings:
    $key_6287 = { 36 ef [2] 42 f7 [2] 05 f5 [2] 42 e4 [2] 0c e8 [2] 00 e2 [2] 17 e9 [2] 0c a7 [2] 31 }

  condition:
    any of them
}
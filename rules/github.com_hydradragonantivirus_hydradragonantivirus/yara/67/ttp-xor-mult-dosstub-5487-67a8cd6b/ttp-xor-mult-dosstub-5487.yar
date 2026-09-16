rule TTP_XOR_MULT_DOSStub_5487 {
  strings:
    $key_5487 = { 00 ef [2] 74 f7 [2] 33 f5 [2] 74 e4 [2] 3a e8 [2] 36 e2 [2] 21 e9 [2] 3a a7 [2] 07 }

  condition:
    any of them
}
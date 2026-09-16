rule TTP_XOR_MULT_DOSStub_7487 {
  strings:
    $key_7487 = { 20 ef [2] 54 f7 [2] 13 f5 [2] 54 e4 [2] 1a e8 [2] 16 e2 [2] 01 e9 [2] 1a a7 [2] 27 }

  condition:
    any of them
}
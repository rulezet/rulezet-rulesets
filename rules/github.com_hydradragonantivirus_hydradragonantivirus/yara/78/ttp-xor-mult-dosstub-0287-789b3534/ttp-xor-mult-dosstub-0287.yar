rule TTP_XOR_MULT_DOSStub_0287 {
  strings:
    $key_0287 = { 56 ef [2] 22 f7 [2] 65 f5 [2] 22 e4 [2] 6c e8 [2] 60 e2 [2] 77 e9 [2] 6c a7 [2] 51 }

  condition:
    any of them
}
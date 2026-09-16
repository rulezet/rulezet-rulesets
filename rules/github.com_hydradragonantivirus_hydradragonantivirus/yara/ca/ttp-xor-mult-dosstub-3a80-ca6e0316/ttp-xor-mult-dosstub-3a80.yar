rule TTP_XOR_MULT_DOSStub_3a80 {
  strings:
    $key_3a80 = { 6e e8 [2] 1a f0 [2] 5d f2 [2] 1a e3 [2] 54 ef [2] 58 e5 [2] 4f ee [2] 54 a0 [2] 69 }

  condition:
    any of them
}
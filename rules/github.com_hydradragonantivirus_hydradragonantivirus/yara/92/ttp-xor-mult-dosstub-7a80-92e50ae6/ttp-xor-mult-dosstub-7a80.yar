rule TTP_XOR_MULT_DOSStub_7a80 {
  strings:
    $key_7a80 = { 2e e8 [2] 5a f0 [2] 1d f2 [2] 5a e3 [2] 14 ef [2] 18 e5 [2] 0f ee [2] 14 a0 [2] 29 }

  condition:
    any of them
}
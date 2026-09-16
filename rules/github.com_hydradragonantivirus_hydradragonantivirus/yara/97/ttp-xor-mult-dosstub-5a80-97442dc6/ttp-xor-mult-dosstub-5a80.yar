rule TTP_XOR_MULT_DOSStub_5a80 {
  strings:
    $key_5a80 = { 0e e8 [2] 7a f0 [2] 3d f2 [2] 7a e3 [2] 34 ef [2] 38 e5 [2] 2f ee [2] 34 a0 [2] 09 }

  condition:
    any of them
}
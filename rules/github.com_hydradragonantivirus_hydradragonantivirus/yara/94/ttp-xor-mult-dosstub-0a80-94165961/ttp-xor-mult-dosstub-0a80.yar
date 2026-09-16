rule TTP_XOR_MULT_DOSStub_0a80 {
  strings:
    $key_0a80 = { 5e e8 [2] 2a f0 [2] 6d f2 [2] 2a e3 [2] 64 ef [2] 68 e5 [2] 7f ee [2] 64 a0 [2] 59 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6a80 {
  strings:
    $key_6a80 = { 3e e8 [2] 4a f0 [2] 0d f2 [2] 4a e3 [2] 04 ef [2] 08 e5 [2] 1f ee [2] 04 a0 [2] 39 }

  condition:
    any of them
}
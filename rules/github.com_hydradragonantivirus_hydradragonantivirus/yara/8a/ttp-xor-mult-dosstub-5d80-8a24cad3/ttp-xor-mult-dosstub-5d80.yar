rule TTP_XOR_MULT_DOSStub_5d80 {
  strings:
    $key_5d80 = { 09 e8 [2] 7d f0 [2] 3a f2 [2] 7d e3 [2] 33 ef [2] 3f e5 [2] 28 ee [2] 33 a0 [2] 0e }

  condition:
    any of them
}
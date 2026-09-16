rule TTP_XOR_MULT_DOSStub_2d80 {
  strings:
    $key_2d80 = { 79 e8 [2] 0d f0 [2] 4a f2 [2] 0d e3 [2] 43 ef [2] 4f e5 [2] 58 ee [2] 43 a0 [2] 7e }

  condition:
    any of them
}
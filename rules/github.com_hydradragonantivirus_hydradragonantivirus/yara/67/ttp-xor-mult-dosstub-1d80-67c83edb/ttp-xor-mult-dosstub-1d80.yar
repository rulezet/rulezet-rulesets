rule TTP_XOR_MULT_DOSStub_1d80 {
  strings:
    $key_1d80 = { 49 e8 [2] 3d f0 [2] 7a f2 [2] 3d e3 [2] 73 ef [2] 7f e5 [2] 68 ee [2] 73 a0 [2] 4e }

  condition:
    any of them
}
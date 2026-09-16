rule TTP_XOR_MULT_DOSStub_6d80 {
  strings:
    $key_6d80 = { 39 e8 [2] 4d f0 [2] 0a f2 [2] 4d e3 [2] 03 ef [2] 0f e5 [2] 18 ee [2] 03 a0 [2] 3e }

  condition:
    any of them
}
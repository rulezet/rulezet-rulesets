rule TTP_XOR_MULT_DOSStub_3a86 {
  strings:
    $key_3a86 = { 6e ee [2] 1a f6 [2] 5d f4 [2] 1a e5 [2] 54 e9 [2] 58 e3 [2] 4f e8 [2] 54 a6 [2] 69 }

  condition:
    any of them
}
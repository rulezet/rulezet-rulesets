rule TTP_XOR_MULT_DOSStub_5897 {
  strings:
    $key_5897 = { 0c ff [2] 78 e7 [2] 3f e5 [2] 78 f4 [2] 36 f8 [2] 3a f2 [2] 2d f9 [2] 36 b7 [2] 0b }

  condition:
    any of them
}
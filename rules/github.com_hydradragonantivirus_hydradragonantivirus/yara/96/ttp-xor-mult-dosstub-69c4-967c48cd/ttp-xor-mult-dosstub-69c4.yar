rule TTP_XOR_MULT_DOSStub_69c4 {
  strings:
    $key_69c4 = { 3d ac [2] 49 b4 [2] 0e b6 [2] 49 a7 [2] 07 ab [2] 0b a1 [2] 1c aa [2] 07 e4 [2] 3a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_69c6 {
  strings:
    $key_69c6 = { 3d ae [2] 49 b6 [2] 0e b4 [2] 49 a5 [2] 07 a9 [2] 0b a3 [2] 1c a8 [2] 07 e6 [2] 3a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_69c1 {
  strings:
    $key_69c1 = { 3d a9 [2] 49 b1 [2] 0e b3 [2] 49 a2 [2] 07 ae [2] 0b a4 [2] 1c af [2] 07 e1 [2] 3a }

  condition:
    any of them
}
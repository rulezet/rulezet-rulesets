rule TTP_XOR_MULT_DOSStub_69c2 {
  strings:
    $key_69c2 = { 3d aa [2] 49 b2 [2] 0e b0 [2] 49 a1 [2] 07 ad [2] 0b a7 [2] 1c ac [2] 07 e2 [2] 3a }

  condition:
    any of them
}
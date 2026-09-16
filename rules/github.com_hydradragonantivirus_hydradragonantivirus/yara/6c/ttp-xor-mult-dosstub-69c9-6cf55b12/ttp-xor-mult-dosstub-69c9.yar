rule TTP_XOR_MULT_DOSStub_69c9 {
  strings:
    $key_69c9 = { 3d a1 [2] 49 b9 [2] 0e bb [2] 49 aa [2] 07 a6 [2] 0b ac [2] 1c a7 [2] 07 e9 [2] 3a }

  condition:
    any of them
}
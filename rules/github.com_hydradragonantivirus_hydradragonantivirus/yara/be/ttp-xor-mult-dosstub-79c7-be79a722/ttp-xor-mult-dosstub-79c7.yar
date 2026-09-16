rule TTP_XOR_MULT_DOSStub_79c7 {
  strings:
    $key_79c7 = { 2d af [2] 59 b7 [2] 1e b5 [2] 59 a4 [2] 17 a8 [2] 1b a2 [2] 0c a9 [2] 17 e7 [2] 2a }

  condition:
    any of them
}
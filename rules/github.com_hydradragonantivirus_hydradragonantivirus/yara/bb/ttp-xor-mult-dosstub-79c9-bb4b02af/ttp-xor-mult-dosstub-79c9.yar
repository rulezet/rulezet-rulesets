rule TTP_XOR_MULT_DOSStub_79c9 {
  strings:
    $key_79c9 = { 2d a1 [2] 59 b9 [2] 1e bb [2] 59 aa [2] 17 a6 [2] 1b ac [2] 0c a7 [2] 17 e9 [2] 2a }

  condition:
    any of them
}
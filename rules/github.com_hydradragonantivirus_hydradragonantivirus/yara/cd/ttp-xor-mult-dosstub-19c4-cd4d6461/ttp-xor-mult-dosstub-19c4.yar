rule TTP_XOR_MULT_DOSStub_19c4 {
  strings:
    $key_19c4 = { 4d ac [2] 39 b4 [2] 7e b6 [2] 39 a7 [2] 77 ab [2] 7b a1 [2] 6c aa [2] 77 e4 [2] 4a }

  condition:
    any of them
}
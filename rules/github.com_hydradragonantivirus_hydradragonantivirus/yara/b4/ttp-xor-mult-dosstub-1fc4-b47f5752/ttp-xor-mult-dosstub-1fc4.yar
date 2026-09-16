rule TTP_XOR_MULT_DOSStub_1fc4 {
  strings:
    $key_1fc4 = { 4b ac [2] 3f b4 [2] 78 b6 [2] 3f a7 [2] 71 ab [2] 7d a1 [2] 6a aa [2] 71 e4 [2] 4c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5fc4 {
  strings:
    $key_5fc4 = { 0b ac [2] 7f b4 [2] 38 b6 [2] 7f a7 [2] 31 ab [2] 3d a1 [2] 2a aa [2] 31 e4 [2] 0c }

  condition:
    any of them
}
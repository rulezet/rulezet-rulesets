rule TTP_XOR_MULT_DOSStub_2fc4 {
  strings:
    $key_2fc4 = { 7b ac [2] 0f b4 [2] 48 b6 [2] 0f a7 [2] 41 ab [2] 4d a1 [2] 5a aa [2] 41 e4 [2] 7c }

  condition:
    any of them
}
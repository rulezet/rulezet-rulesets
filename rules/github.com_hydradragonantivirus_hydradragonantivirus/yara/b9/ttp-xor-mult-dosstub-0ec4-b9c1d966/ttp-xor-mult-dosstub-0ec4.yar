rule TTP_XOR_MULT_DOSStub_0ec4 {
  strings:
    $key_0ec4 = { 5a ac [2] 2e b4 [2] 69 b6 [2] 2e a7 [2] 60 ab [2] 6c a1 [2] 7b aa [2] 60 e4 [2] 5d }

  condition:
    any of them
}
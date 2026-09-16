rule TTP_XOR_MULT_DOSStub_3ec4 {
  strings:
    $key_3ec4 = { 6a ac [2] 1e b4 [2] 59 b6 [2] 1e a7 [2] 50 ab [2] 5c a1 [2] 4b aa [2] 50 e4 [2] 6d }

  condition:
    any of them
}
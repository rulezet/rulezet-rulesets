rule TTP_XOR_MULT_DOSStub_7ec4 {
  strings:
    $key_7ec4 = { 2a ac [2] 5e b4 [2] 19 b6 [2] 5e a7 [2] 10 ab [2] 1c a1 [2] 0b aa [2] 10 e4 [2] 2d }

  condition:
    any of them
}
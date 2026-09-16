rule TTP_XOR_MULT_DOSStub_15c3 {
  strings:
    $key_15c3 = { 41 ab [2] 35 b3 [2] 72 b1 [2] 35 a0 [2] 7b ac [2] 77 a6 [2] 60 ad [2] 7b e3 [2] 46 }

  condition:
    any of them
}
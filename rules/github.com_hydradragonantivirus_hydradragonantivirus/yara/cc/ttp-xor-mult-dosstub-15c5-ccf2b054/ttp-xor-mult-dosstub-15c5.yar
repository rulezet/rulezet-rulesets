rule TTP_XOR_MULT_DOSStub_15c5 {
  strings:
    $key_15c5 = { 41 ad [2] 35 b5 [2] 72 b7 [2] 35 a6 [2] 7b aa [2] 77 a0 [2] 60 ab [2] 7b e5 [2] 46 }

  condition:
    any of them
}
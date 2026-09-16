rule TTP_XOR_MULT_DOSStub_55c5 {
  strings:
    $key_55c5 = { 01 ad [2] 75 b5 [2] 32 b7 [2] 75 a6 [2] 3b aa [2] 37 a0 [2] 20 ab [2] 3b e5 [2] 06 }

  condition:
    any of them
}
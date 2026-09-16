rule TTP_XOR_MULT_DOSStub_55c0 {
  strings:
    $key_55c0 = { 01 a8 [2] 75 b0 [2] 32 b2 [2] 75 a3 [2] 3b af [2] 37 a5 [2] 20 ae [2] 3b e0 [2] 06 }

  condition:
    any of them
}
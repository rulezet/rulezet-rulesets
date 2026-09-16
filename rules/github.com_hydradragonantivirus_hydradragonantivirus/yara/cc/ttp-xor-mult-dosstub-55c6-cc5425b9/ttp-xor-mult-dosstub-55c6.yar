rule TTP_XOR_MULT_DOSStub_55c6 {
  strings:
    $key_55c6 = { 01 ae [2] 75 b6 [2] 32 b4 [2] 75 a5 [2] 3b a9 [2] 37 a3 [2] 20 a8 [2] 3b e6 [2] 06 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_35c6 {
  strings:
    $key_35c6 = { 61 ae [2] 15 b6 [2] 52 b4 [2] 15 a5 [2] 5b a9 [2] 57 a3 [2] 40 a8 [2] 5b e6 [2] 66 }

  condition:
    any of them
}
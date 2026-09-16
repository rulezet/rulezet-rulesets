rule TTP_XOR_MULT_DOSStub_02c6 {
  strings:
    $key_02c6 = { 56 ae [2] 22 b6 [2] 65 b4 [2] 22 a5 [2] 6c a9 [2] 60 a3 [2] 77 a8 [2] 6c e6 [2] 51 }

  condition:
    any of them
}
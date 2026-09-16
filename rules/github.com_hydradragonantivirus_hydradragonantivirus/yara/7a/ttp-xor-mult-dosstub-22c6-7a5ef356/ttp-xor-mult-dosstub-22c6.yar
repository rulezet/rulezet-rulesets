rule TTP_XOR_MULT_DOSStub_22c6 {
  strings:
    $key_22c6 = { 76 ae [2] 02 b6 [2] 45 b4 [2] 02 a5 [2] 4c a9 [2] 40 a3 [2] 57 a8 [2] 4c e6 [2] 71 }

  condition:
    any of them
}
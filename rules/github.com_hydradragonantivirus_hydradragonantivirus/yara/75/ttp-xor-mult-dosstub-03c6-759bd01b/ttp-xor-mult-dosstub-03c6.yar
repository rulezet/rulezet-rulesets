rule TTP_XOR_MULT_DOSStub_03c6 {
  strings:
    $key_03c6 = { 57 ae [2] 23 b6 [2] 64 b4 [2] 23 a5 [2] 6d a9 [2] 61 a3 [2] 76 a8 [2] 6d e6 [2] 50 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_23c6 {
  strings:
    $key_23c6 = { 77 ae [2] 03 b6 [2] 44 b4 [2] 03 a5 [2] 4d a9 [2] 41 a3 [2] 56 a8 [2] 4d e6 [2] 70 }

  condition:
    any of them
}
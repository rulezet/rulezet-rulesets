rule TTP_XOR_MULT_DOSStub_10c6 {
  strings:
    $key_10c6 = { 44 ae [2] 30 b6 [2] 77 b4 [2] 30 a5 [2] 7e a9 [2] 72 a3 [2] 65 a8 [2] 7e e6 [2] 43 }

  condition:
    any of them
}
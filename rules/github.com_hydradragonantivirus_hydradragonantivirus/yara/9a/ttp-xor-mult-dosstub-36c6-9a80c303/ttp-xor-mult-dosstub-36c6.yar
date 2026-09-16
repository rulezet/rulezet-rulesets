rule TTP_XOR_MULT_DOSStub_36c6 {
  strings:
    $key_36c6 = { 62 ae [2] 16 b6 [2] 51 b4 [2] 16 a5 [2] 58 a9 [2] 54 a3 [2] 43 a8 [2] 58 e6 [2] 65 }

  condition:
    any of them
}
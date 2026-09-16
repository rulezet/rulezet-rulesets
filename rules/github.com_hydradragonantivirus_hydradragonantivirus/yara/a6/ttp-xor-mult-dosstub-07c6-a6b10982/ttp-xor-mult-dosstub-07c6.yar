rule TTP_XOR_MULT_DOSStub_07c6 {
  strings:
    $key_07c6 = { 53 ae [2] 27 b6 [2] 60 b4 [2] 27 a5 [2] 69 a9 [2] 65 a3 [2] 72 a8 [2] 69 e6 [2] 54 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_16c6 {
  strings:
    $key_16c6 = { 42 ae [2] 36 b6 [2] 71 b4 [2] 36 a5 [2] 78 a9 [2] 74 a3 [2] 63 a8 [2] 78 e6 [2] 45 }

  condition:
    any of them
}
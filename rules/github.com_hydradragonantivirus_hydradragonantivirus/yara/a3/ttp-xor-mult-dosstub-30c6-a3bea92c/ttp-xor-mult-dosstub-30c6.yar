rule TTP_XOR_MULT_DOSStub_30c6 {
  strings:
    $key_30c6 = { 64 ae [2] 10 b6 [2] 57 b4 [2] 10 a5 [2] 5e a9 [2] 52 a3 [2] 45 a8 [2] 5e e6 [2] 63 }

  condition:
    any of them
}
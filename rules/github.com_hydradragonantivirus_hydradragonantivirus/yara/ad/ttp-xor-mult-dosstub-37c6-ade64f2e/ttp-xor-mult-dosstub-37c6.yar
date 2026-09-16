rule TTP_XOR_MULT_DOSStub_37c6 {
  strings:
    $key_37c6 = { 63 ae [2] 17 b6 [2] 50 b4 [2] 17 a5 [2] 59 a9 [2] 55 a3 [2] 42 a8 [2] 59 e6 [2] 64 }

  condition:
    any of them
}
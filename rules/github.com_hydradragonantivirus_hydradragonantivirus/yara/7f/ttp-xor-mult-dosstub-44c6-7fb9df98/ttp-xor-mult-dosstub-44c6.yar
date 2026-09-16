rule TTP_XOR_MULT_DOSStub_44c6 {
  strings:
    $key_44c6 = { 10 ae [2] 64 b6 [2] 23 b4 [2] 64 a5 [2] 2a a9 [2] 26 a3 [2] 31 a8 [2] 2a e6 [2] 17 }

  condition:
    any of them
}
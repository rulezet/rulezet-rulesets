rule TTP_XOR_MULT_DOSStub_34c6 {
  strings:
    $key_34c6 = { 60 ae [2] 14 b6 [2] 53 b4 [2] 14 a5 [2] 5a a9 [2] 56 a3 [2] 41 a8 [2] 5a e6 [2] 67 }

  condition:
    any of them
}
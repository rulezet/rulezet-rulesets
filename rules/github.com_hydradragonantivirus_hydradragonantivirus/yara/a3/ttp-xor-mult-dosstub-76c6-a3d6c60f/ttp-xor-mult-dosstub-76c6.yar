rule TTP_XOR_MULT_DOSStub_76c6 {
  strings:
    $key_76c6 = { 22 ae [2] 56 b6 [2] 11 b4 [2] 56 a5 [2] 18 a9 [2] 14 a3 [2] 03 a8 [2] 18 e6 [2] 25 }

  condition:
    any of them
}
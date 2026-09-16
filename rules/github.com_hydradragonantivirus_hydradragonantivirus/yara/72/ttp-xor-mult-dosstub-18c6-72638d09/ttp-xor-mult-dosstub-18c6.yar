rule TTP_XOR_MULT_DOSStub_18c6 {
  strings:
    $key_18c6 = { 4c ae [2] 38 b6 [2] 7f b4 [2] 38 a5 [2] 76 a9 [2] 7a a3 [2] 6d a8 [2] 76 e6 [2] 4b }

  condition:
    any of them
}
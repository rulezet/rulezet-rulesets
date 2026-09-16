rule TTP_XOR_MULT_DOSStub_38c6 {
  strings:
    $key_38c6 = { 6c ae [2] 18 b6 [2] 5f b4 [2] 18 a5 [2] 56 a9 [2] 5a a3 [2] 4d a8 [2] 56 e6 [2] 6b }

  condition:
    any of them
}
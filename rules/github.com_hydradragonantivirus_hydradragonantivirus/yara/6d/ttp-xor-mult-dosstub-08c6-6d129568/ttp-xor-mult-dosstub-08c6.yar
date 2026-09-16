rule TTP_XOR_MULT_DOSStub_08c6 {
  strings:
    $key_08c6 = { 5c ae [2] 28 b6 [2] 6f b4 [2] 28 a5 [2] 66 a9 [2] 6a a3 [2] 7d a8 [2] 66 e6 [2] 5b }

  condition:
    any of them
}
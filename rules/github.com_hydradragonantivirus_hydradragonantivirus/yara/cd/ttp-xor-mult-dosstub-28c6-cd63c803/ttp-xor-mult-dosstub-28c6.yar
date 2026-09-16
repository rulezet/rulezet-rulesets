rule TTP_XOR_MULT_DOSStub_28c6 {
  strings:
    $key_28c6 = { 7c ae [2] 08 b6 [2] 4f b4 [2] 08 a5 [2] 46 a9 [2] 4a a3 [2] 5d a8 [2] 46 e6 [2] 7b }

  condition:
    any of them
}
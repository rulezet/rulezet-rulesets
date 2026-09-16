rule TTP_XOR_MULT_DOSStub_68c6 {
  strings:
    $key_68c6 = { 3c ae [2] 48 b6 [2] 0f b4 [2] 48 a5 [2] 06 a9 [2] 0a a3 [2] 1d a8 [2] 06 e6 [2] 3b }

  condition:
    any of them
}
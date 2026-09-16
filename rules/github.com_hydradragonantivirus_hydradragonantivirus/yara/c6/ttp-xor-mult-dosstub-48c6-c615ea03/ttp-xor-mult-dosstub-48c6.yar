rule TTP_XOR_MULT_DOSStub_48c6 {
  strings:
    $key_48c6 = { 1c ae [2] 68 b6 [2] 2f b4 [2] 68 a5 [2] 26 a9 [2] 2a a3 [2] 3d a8 [2] 26 e6 [2] 1b }

  condition:
    any of them
}
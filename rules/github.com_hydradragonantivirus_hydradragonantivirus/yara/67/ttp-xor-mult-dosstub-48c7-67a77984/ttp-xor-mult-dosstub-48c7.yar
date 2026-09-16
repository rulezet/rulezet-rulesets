rule TTP_XOR_MULT_DOSStub_48c7 {
  strings:
    $key_48c7 = { 1c af [2] 68 b7 [2] 2f b5 [2] 68 a4 [2] 26 a8 [2] 2a a2 [2] 3d a9 [2] 26 e7 [2] 1b }

  condition:
    any of them
}
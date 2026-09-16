rule TTP_XOR_MULT_DOSStub_68c7 {
  strings:
    $key_68c7 = { 3c af [2] 48 b7 [2] 0f b5 [2] 48 a4 [2] 06 a8 [2] 0a a2 [2] 1d a9 [2] 06 e7 [2] 3b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3196 {
  strings:
    $key_3196 = { 65 fe [2] 11 e6 [2] 56 e4 [2] 11 f5 [2] 5f f9 [2] 53 f3 [2] 44 f8 [2] 5f b6 [2] 62 }

  condition:
    any of them
}
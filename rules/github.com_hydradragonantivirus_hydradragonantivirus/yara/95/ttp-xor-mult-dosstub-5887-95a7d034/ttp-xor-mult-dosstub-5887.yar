rule TTP_XOR_MULT_DOSStub_5887 {
  strings:
    $key_5887 = { 0c ef [2] 78 f7 [2] 3f f5 [2] 78 e4 [2] 36 e8 [2] 3a e2 [2] 2d e9 [2] 36 a7 [2] 0b }

  condition:
    any of them
}
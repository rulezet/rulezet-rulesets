rule TTP_XOR_MULT_DOSStub_6887 {
  strings:
    $key_6887 = { 3c ef [2] 48 f7 [2] 0f f5 [2] 48 e4 [2] 06 e8 [2] 0a e2 [2] 1d e9 [2] 06 a7 [2] 3b }

  condition:
    any of them
}
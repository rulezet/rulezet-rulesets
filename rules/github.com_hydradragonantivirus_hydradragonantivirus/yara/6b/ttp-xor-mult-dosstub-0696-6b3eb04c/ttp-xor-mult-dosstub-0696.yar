rule TTP_XOR_MULT_DOSStub_0696 {
  strings:
    $key_0696 = { 52 fe [2] 26 e6 [2] 61 e4 [2] 26 f5 [2] 68 f9 [2] 64 f3 [2] 73 f8 [2] 68 b6 [2] 55 }

  condition:
    any of them
}
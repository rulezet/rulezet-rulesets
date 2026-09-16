rule TTP_XOR_MULT_DOSStub_0687 {
  strings:
    $key_0687 = { 52 ef [2] 26 f7 [2] 61 f5 [2] 26 e4 [2] 68 e8 [2] 64 e2 [2] 73 e9 [2] 68 a7 [2] 55 }

  condition:
    any of them
}
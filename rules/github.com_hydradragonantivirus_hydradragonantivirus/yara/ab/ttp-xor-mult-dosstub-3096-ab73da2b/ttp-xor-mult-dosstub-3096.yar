rule TTP_XOR_MULT_DOSStub_3096 {
  strings:
    $key_3096 = { 64 fe [2] 10 e6 [2] 57 e4 [2] 10 f5 [2] 5e f9 [2] 52 f3 [2] 45 f8 [2] 5e b6 [2] 63 }

  condition:
    any of them
}
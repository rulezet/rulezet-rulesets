rule TTP_XOR_MULT_DOSStub_4496 {
  strings:
    $key_4496 = { 10 fe [2] 64 e6 [2] 23 e4 [2] 64 f5 [2] 2a f9 [2] 26 f3 [2] 31 f8 [2] 2a b6 [2] 17 }

  condition:
    any of them
}
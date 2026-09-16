rule TTP_XOR_MULT_DOSStub_6496 {
  strings:
    $key_6496 = { 30 fe [2] 44 e6 [2] 03 e4 [2] 44 f5 [2] 0a f9 [2] 06 f3 [2] 11 f8 [2] 0a b6 [2] 37 }

  condition:
    any of them
}
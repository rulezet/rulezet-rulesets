rule TTP_XOR_MULT_DOSStub_3496 {
  strings:
    $key_3496 = { 60 fe [2] 14 e6 [2] 53 e4 [2] 14 f5 [2] 5a f9 [2] 56 f3 [2] 41 f8 [2] 5a b6 [2] 67 }

  condition:
    any of them
}
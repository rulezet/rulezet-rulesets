rule TTP_XOR_MULT_DOSStub_7496 {
  strings:
    $key_7496 = { 20 fe [2] 54 e6 [2] 13 e4 [2] 54 f5 [2] 1a f9 [2] 16 f3 [2] 01 f8 [2] 1a b6 [2] 27 }

  condition:
    any of them
}
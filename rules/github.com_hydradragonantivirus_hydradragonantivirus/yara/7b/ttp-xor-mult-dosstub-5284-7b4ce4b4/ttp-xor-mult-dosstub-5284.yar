rule TTP_XOR_MULT_DOSStub_5284 {
  strings:
    $key_5284 = { 06 ec [2] 72 f4 [2] 35 f6 [2] 72 e7 [2] 3c eb [2] 30 e1 [2] 27 ea [2] 3c a4 [2] 01 }

  condition:
    any of them
}
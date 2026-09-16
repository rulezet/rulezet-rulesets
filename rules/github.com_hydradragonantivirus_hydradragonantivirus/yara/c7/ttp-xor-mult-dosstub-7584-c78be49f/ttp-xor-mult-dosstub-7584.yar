rule TTP_XOR_MULT_DOSStub_7584 {
  strings:
    $key_7584 = { 21 ec [2] 55 f4 [2] 12 f6 [2] 55 e7 [2] 1b eb [2] 17 e1 [2] 00 ea [2] 1b a4 [2] 26 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4584 {
  strings:
    $key_4584 = { 11 ec [2] 65 f4 [2] 22 f6 [2] 65 e7 [2] 2b eb [2] 27 e1 [2] 30 ea [2] 2b a4 [2] 16 }

  condition:
    any of them
}
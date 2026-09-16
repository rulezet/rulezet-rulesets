rule TTP_XOR_MULT_DOSStub_0584 {
  strings:
    $key_0584 = { 51 ec [2] 25 f4 [2] 62 f6 [2] 25 e7 [2] 6b eb [2] 67 e1 [2] 70 ea [2] 6b a4 [2] 56 }

  condition:
    any of them
}
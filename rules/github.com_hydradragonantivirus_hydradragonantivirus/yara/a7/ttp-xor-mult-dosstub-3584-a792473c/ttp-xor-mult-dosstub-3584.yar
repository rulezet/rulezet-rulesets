rule TTP_XOR_MULT_DOSStub_3584 {
  strings:
    $key_3584 = { 61 ec [2] 15 f4 [2] 52 f6 [2] 15 e7 [2] 5b eb [2] 57 e1 [2] 40 ea [2] 5b a4 [2] 66 }

  condition:
    any of them
}
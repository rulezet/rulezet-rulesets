rule TTP_XOR_MULT_DOSStub_4184 {
  strings:
    $key_4184 = { 15 ec [2] 61 f4 [2] 26 f6 [2] 61 e7 [2] 2f eb [2] 23 e1 [2] 34 ea [2] 2f a4 [2] 12 }

  condition:
    any of them
}
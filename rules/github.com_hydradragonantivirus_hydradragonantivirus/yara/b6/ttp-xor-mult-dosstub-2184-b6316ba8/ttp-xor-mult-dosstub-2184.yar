rule TTP_XOR_MULT_DOSStub_2184 {
  strings:
    $key_2184 = { 75 ec [2] 01 f4 [2] 46 f6 [2] 01 e7 [2] 4f eb [2] 43 e1 [2] 54 ea [2] 4f a4 [2] 72 }

  condition:
    any of them
}
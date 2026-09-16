rule TTP_XOR_MULT_DOSStub_5184 {
  strings:
    $key_5184 = { 05 ec [2] 71 f4 [2] 36 f6 [2] 71 e7 [2] 3f eb [2] 33 e1 [2] 24 ea [2] 3f a4 [2] 02 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5a89 {
  strings:
    $key_5a89 = { 0e e1 [2] 7a f9 [2] 3d fb [2] 7a ea [2] 34 e6 [2] 38 ec [2] 2f e7 [2] 34 a9 [2] 09 }

  condition:
    any of them
}
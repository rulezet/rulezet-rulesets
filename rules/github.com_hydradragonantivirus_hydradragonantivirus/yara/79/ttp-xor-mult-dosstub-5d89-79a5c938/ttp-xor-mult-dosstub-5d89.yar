rule TTP_XOR_MULT_DOSStub_5d89 {
  strings:
    $key_5d89 = { 09 e1 [2] 7d f9 [2] 3a fb [2] 7d ea [2] 33 e6 [2] 3f ec [2] 28 e7 [2] 33 a9 [2] 0e }

  condition:
    any of them
}
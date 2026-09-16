rule TTP_XOR_MULT_DOSStub_5d84 {
  strings:
    $key_5d84 = { 09 ec [2] 7d f4 [2] 3a f6 [2] 7d e7 [2] 33 eb [2] 3f e1 [2] 28 ea [2] 33 a4 [2] 0e }

  condition:
    any of them
}
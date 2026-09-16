rule TTP_XOR_MULT_DOSStub_4d84 {
  strings:
    $key_4d84 = { 19 ec [2] 6d f4 [2] 2a f6 [2] 6d e7 [2] 23 eb [2] 2f e1 [2] 38 ea [2] 23 a4 [2] 1e }

  condition:
    any of them
}
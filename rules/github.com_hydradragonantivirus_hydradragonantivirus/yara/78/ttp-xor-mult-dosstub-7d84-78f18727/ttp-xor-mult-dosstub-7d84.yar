rule TTP_XOR_MULT_DOSStub_7d84 {
  strings:
    $key_7d84 = { 29 ec [2] 5d f4 [2] 1a f6 [2] 5d e7 [2] 13 eb [2] 1f e1 [2] 08 ea [2] 13 a4 [2] 2e }

  condition:
    any of them
}
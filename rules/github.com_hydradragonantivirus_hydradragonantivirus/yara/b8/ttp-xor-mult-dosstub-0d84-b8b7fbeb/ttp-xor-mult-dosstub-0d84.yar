rule TTP_XOR_MULT_DOSStub_0d84 {
  strings:
    $key_0d84 = { 59 ec [2] 2d f4 [2] 6a f6 [2] 2d e7 [2] 63 eb [2] 6f e1 [2] 78 ea [2] 63 a4 [2] 5e }

  condition:
    any of them
}
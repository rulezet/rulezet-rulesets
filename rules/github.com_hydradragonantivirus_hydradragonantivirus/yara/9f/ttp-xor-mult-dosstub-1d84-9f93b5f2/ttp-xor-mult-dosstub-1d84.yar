rule TTP_XOR_MULT_DOSStub_1d84 {
  strings:
    $key_1d84 = { 49 ec [2] 3d f4 [2] 7a f6 [2] 3d e7 [2] 73 eb [2] 7f e1 [2] 68 ea [2] 73 a4 [2] 4e }

  condition:
    any of them
}
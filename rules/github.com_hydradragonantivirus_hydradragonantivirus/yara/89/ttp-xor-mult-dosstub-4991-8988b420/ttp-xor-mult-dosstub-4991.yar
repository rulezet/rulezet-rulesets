rule TTP_XOR_MULT_DOSStub_4991 {
  strings:
    $key_4991 = { 1d f9 [2] 69 e1 [2] 2e e3 [2] 69 f2 [2] 27 fe [2] 2b f4 [2] 3c ff [2] 27 b1 [2] 1a }

  condition:
    any of them
}
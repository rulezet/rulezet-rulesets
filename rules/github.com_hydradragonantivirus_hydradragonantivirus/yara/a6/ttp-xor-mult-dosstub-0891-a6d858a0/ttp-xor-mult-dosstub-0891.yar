rule TTP_XOR_MULT_DOSStub_0891 {
  strings:
    $key_0891 = { 5c f9 [2] 28 e1 [2] 6f e3 [2] 28 f2 [2] 66 fe [2] 6a f4 [2] 7d ff [2] 66 b1 [2] 5b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1891 {
  strings:
    $key_1891 = { 4c f9 [2] 38 e1 [2] 7f e3 [2] 38 f2 [2] 76 fe [2] 7a f4 [2] 6d ff [2] 76 b1 [2] 4b }

  condition:
    any of them
}
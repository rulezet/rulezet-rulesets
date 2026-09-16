rule TTP_XOR_MULT_DOSStub_4891 {
  strings:
    $key_4891 = { 1c f9 [2] 68 e1 [2] 2f e3 [2] 68 f2 [2] 26 fe [2] 2a f4 [2] 3d ff [2] 26 b1 [2] 1b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6891 {
  strings:
    $key_6891 = { 3c f9 [2] 48 e1 [2] 0f e3 [2] 48 f2 [2] 06 fe [2] 0a f4 [2] 1d ff [2] 06 b1 [2] 3b }

  condition:
    any of them
}
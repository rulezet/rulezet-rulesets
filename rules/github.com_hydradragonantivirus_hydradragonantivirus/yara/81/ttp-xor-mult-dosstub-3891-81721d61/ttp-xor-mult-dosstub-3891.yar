rule TTP_XOR_MULT_DOSStub_3891 {
  strings:
    $key_3891 = { 6c f9 [2] 18 e1 [2] 5f e3 [2] 18 f2 [2] 56 fe [2] 5a f4 [2] 4d ff [2] 56 b1 [2] 6b }

  condition:
    any of them
}
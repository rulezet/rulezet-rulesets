rule TTP_XOR_MULT_DOSStub_2891 {
  strings:
    $key_2891 = { 7c f9 [2] 08 e1 [2] 4f e3 [2] 08 f2 [2] 46 fe [2] 4a f4 [2] 5d ff [2] 46 b1 [2] 7b }

  condition:
    any of them
}
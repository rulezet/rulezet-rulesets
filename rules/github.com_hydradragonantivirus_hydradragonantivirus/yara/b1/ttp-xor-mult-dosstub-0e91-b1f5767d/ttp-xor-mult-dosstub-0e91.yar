rule TTP_XOR_MULT_DOSStub_0e91 {
  strings:
    $key_0e91 = { 5a f9 [2] 2e e1 [2] 69 e3 [2] 2e f2 [2] 60 fe [2] 6c f4 [2] 7b ff [2] 60 b1 [2] 5d }

  condition:
    any of them
}
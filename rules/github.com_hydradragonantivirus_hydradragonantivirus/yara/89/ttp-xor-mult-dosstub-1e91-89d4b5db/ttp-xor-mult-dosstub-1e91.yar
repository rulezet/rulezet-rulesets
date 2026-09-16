rule TTP_XOR_MULT_DOSStub_1e91 {
  strings:
    $key_1e91 = { 4a f9 [2] 3e e1 [2] 79 e3 [2] 3e f2 [2] 70 fe [2] 7c f4 [2] 6b ff [2] 70 b1 [2] 4d }

  condition:
    any of them
}
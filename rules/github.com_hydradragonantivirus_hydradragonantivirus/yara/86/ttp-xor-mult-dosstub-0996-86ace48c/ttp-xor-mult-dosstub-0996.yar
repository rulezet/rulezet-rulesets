rule TTP_XOR_MULT_DOSStub_0996 {
  strings:
    $key_0996 = { 5d fe [2] 29 e6 [2] 6e e4 [2] 29 f5 [2] 67 f9 [2] 6b f3 [2] 7c f8 [2] 67 b6 [2] 5a }

  condition:
    any of them
}
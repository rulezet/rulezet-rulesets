rule TTP_XOR_MULT_DOSStub_1996 {
  strings:
    $key_1996 = { 4d fe [2] 39 e6 [2] 7e e4 [2] 39 f5 [2] 77 f9 [2] 7b f3 [2] 6c f8 [2] 77 b6 [2] 4a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7e90 {
  strings:
    $key_7e90 = { 2a f8 [2] 5e e0 [2] 19 e2 [2] 5e f3 [2] 10 ff [2] 1c f5 [2] 0b fe [2] 10 b0 [2] 2d }

  condition:
    any of them
}
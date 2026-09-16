rule TTP_XOR_MULT_DOSStub_3e90 {
  strings:
    $key_3e90 = { 6a f8 [2] 1e e0 [2] 59 e2 [2] 1e f3 [2] 50 ff [2] 5c f5 [2] 4b fe [2] 50 b0 [2] 6d }

  condition:
    any of them
}
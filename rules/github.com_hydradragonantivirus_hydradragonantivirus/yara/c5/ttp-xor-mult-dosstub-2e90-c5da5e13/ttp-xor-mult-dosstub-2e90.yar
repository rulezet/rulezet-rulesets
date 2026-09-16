rule TTP_XOR_MULT_DOSStub_2e90 {
  strings:
    $key_2e90 = { 7a f8 [2] 0e e0 [2] 49 e2 [2] 0e f3 [2] 40 ff [2] 4c f5 [2] 5b fe [2] 40 b0 [2] 7d }

  condition:
    any of them
}
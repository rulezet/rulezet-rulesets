rule TTP_XOR_MULT_DOSStub_fe90 {
  strings:
    $key_fe90 = { aa f8 [2] de e0 [2] 99 e2 [2] de f3 [2] 90 ff [2] 9c f5 [2] 8b fe [2] 90 b0 [2] ad }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2c93 {
  strings:
    $key_2c93 = { 78 fb [2] 0c e3 [2] 4b e1 [2] 0c f0 [2] 42 fc [2] 4e f6 [2] 59 fd [2] 42 b3 [2] 7f }

  condition:
    any of them
}
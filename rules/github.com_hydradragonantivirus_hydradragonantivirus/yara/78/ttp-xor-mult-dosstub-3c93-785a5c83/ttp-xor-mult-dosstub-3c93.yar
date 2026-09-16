rule TTP_XOR_MULT_DOSStub_3c93 {
  strings:
    $key_3c93 = { 68 fb [2] 1c e3 [2] 5b e1 [2] 1c f0 [2] 52 fc [2] 5e f6 [2] 49 fd [2] 52 b3 [2] 6f }

  condition:
    any of them
}
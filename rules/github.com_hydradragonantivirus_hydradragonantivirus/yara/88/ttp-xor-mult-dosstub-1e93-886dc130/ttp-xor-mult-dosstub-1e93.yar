rule TTP_XOR_MULT_DOSStub_1e93 {
  strings:
    $key_1e93 = { 4a fb [2] 3e e3 [2] 79 e1 [2] 3e f0 [2] 70 fc [2] 7c f6 [2] 6b fd [2] 70 b3 [2] 4d }

  condition:
    any of them
}
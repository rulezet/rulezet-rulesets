rule TTP_XOR_MULT_DOSStub_3e93 {
  strings:
    $key_3e93 = { 6a fb [2] 1e e3 [2] 59 e1 [2] 1e f0 [2] 50 fc [2] 5c f6 [2] 4b fd [2] 50 b3 [2] 6d }

  condition:
    any of them
}
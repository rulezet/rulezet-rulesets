rule TTP_XOR_MULT_DOSStub_2e93 {
  strings:
    $key_2e93 = { 7a fb [2] 0e e3 [2] 49 e1 [2] 0e f0 [2] 40 fc [2] 4c f6 [2] 5b fd [2] 40 b3 [2] 7d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_708d {
  strings:
    $key_708d = { 24 e5 [2] 50 fd [2] 17 ff [2] 50 ee [2] 1e e2 [2] 12 e8 [2] 05 e3 [2] 1e ad [2] 23 }

  condition:
    any of them
}
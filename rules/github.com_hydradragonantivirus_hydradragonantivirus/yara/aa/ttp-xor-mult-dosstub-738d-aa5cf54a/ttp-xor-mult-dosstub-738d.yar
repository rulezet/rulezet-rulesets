rule TTP_XOR_MULT_DOSStub_738d {
  strings:
    $key_738d = { 27 e5 [2] 53 fd [2] 14 ff [2] 53 ee [2] 1d e2 [2] 11 e8 [2] 06 e3 [2] 1d ad [2] 20 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_638d {
  strings:
    $key_638d = { 37 e5 [2] 43 fd [2] 04 ff [2] 43 ee [2] 0d e2 [2] 01 e8 [2] 16 e3 [2] 0d ad [2] 30 }

  condition:
    any of them
}
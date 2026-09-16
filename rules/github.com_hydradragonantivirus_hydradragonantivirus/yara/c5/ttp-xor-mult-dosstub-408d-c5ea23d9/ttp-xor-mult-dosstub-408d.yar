rule TTP_XOR_MULT_DOSStub_408d {
  strings:
    $key_408d = { 14 e5 [2] 60 fd [2] 27 ff [2] 60 ee [2] 2e e2 [2] 22 e8 [2] 35 e3 [2] 2e ad [2] 13 }

  condition:
    any of them
}
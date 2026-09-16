rule TTP_XOR_MULT_DOSStub_448d {
  strings:
    $key_448d = { 10 e5 [2] 64 fd [2] 23 ff [2] 64 ee [2] 2a e2 [2] 26 e8 [2] 31 e3 [2] 2a ad [2] 17 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_528d {
  strings:
    $key_528d = { 06 e5 [2] 72 fd [2] 35 ff [2] 72 ee [2] 3c e2 [2] 30 e8 [2] 27 e3 [2] 3c ad [2] 01 }

  condition:
    any of them
}
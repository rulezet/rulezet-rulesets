rule TTP_XOR_MULT_DOSStub_078d {
  strings:
    $key_078d = { 53 e5 [2] 27 fd [2] 60 ff [2] 27 ee [2] 69 e2 [2] 65 e8 [2] 72 e3 [2] 69 ad [2] 54 }

  condition:
    any of them
}
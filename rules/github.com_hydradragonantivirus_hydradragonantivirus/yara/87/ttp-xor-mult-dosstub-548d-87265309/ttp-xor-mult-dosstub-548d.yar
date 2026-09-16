rule TTP_XOR_MULT_DOSStub_548d {
  strings:
    $key_548d = { 00 e5 [2] 74 fd [2] 33 ff [2] 74 ee [2] 3a e2 [2] 36 e8 [2] 21 e3 [2] 3a ad [2] 07 }

  condition:
    any of them
}
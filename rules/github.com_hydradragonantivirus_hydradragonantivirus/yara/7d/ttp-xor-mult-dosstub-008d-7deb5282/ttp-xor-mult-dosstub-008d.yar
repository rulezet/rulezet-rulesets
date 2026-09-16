rule TTP_XOR_MULT_DOSStub_008d {
  strings:
    $key_008d = { 54 e5 [2] 20 fd [2] 67 ff [2] 20 ee [2] 6e e2 [2] 62 e8 [2] 75 e3 [2] 6e ad [2] 53 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_368d {
  strings:
    $key_368d = { 62 e5 [2] 16 fd [2] 51 ff [2] 16 ee [2] 58 e2 [2] 54 e8 [2] 43 e3 [2] 58 ad [2] 65 }

  condition:
    any of them
}
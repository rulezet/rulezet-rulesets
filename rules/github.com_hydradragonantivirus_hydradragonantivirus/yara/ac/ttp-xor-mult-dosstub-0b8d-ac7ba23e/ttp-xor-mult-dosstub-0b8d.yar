rule TTP_XOR_MULT_DOSStub_0b8d {
  strings:
    $key_0b8d = { 5f e5 [2] 2b fd [2] 6c ff [2] 2b ee [2] 65 e2 [2] 69 e8 [2] 7e e3 [2] 65 ad [2] 58 }

  condition:
    any of them
}
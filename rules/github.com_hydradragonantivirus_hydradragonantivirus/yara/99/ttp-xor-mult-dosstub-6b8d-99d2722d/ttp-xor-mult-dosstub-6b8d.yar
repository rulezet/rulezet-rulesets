rule TTP_XOR_MULT_DOSStub_6b8d {
  strings:
    $key_6b8d = { 3f e5 [2] 4b fd [2] 0c ff [2] 4b ee [2] 05 e2 [2] 09 e8 [2] 1e e3 [2] 05 ad [2] 38 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2b8d {
  strings:
    $key_2b8d = { 7f e5 [2] 0b fd [2] 4c ff [2] 0b ee [2] 45 e2 [2] 49 e8 [2] 5e e3 [2] 45 ad [2] 78 }

  condition:
    any of them
}
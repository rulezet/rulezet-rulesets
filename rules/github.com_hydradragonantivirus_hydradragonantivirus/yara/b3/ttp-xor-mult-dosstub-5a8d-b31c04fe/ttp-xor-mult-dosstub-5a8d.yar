rule TTP_XOR_MULT_DOSStub_5a8d {
  strings:
    $key_5a8d = { 0e e5 [2] 7a fd [2] 3d ff [2] 7a ee [2] 34 e2 [2] 38 e8 [2] 2f e3 [2] 34 ad [2] 09 }

  condition:
    any of them
}
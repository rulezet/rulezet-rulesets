rule TTP_XOR_MULT_DOSStub_6a8d {
  strings:
    $key_6a8d = { 3e e5 [2] 4a fd [2] 0d ff [2] 4a ee [2] 04 e2 [2] 08 e8 [2] 1f e3 [2] 04 ad [2] 39 }

  condition:
    any of them
}
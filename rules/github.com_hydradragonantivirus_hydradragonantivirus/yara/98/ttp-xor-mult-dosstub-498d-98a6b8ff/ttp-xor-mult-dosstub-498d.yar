rule TTP_XOR_MULT_DOSStub_498d {
  strings:
    $key_498d = { 1d e5 [2] 69 fd [2] 2e ff [2] 69 ee [2] 27 e2 [2] 2b e8 [2] 3c e3 [2] 27 ad [2] 1a }

  condition:
    any of them
}
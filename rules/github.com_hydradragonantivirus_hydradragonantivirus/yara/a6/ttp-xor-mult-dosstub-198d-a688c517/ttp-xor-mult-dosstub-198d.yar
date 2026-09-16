rule TTP_XOR_MULT_DOSStub_198d {
  strings:
    $key_198d = { 4d e5 [2] 39 fd [2] 7e ff [2] 39 ee [2] 77 e2 [2] 7b e8 [2] 6c e3 [2] 77 ad [2] 4a }

  condition:
    any of them
}
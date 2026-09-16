rule TTP_XOR_MULT_DOSStub_598d {
  strings:
    $key_598d = { 0d e5 [2] 79 fd [2] 3e ff [2] 79 ee [2] 37 e2 [2] 3b e8 [2] 2c e3 [2] 37 ad [2] 0a }

  condition:
    any of them
}
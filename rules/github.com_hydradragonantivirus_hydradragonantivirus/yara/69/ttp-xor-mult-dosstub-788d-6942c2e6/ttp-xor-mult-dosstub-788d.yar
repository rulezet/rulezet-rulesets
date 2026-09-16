rule TTP_XOR_MULT_DOSStub_788d {
  strings:
    $key_788d = { 2c e5 [2] 58 fd [2] 1f ff [2] 58 ee [2] 16 e2 [2] 1a e8 [2] 0d e3 [2] 16 ad [2] 2b }

  condition:
    any of them
}
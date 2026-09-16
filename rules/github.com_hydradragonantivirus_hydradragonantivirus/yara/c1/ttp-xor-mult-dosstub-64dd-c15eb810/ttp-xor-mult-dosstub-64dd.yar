rule TTP_XOR_MULT_DOSStub_64dd {
  strings:
    $key_64dd = { 30 b5 [2] 44 ad [2] 03 af [2] 44 be [2] 0a b2 [2] 06 b8 [2] 11 b3 [2] 0a fd [2] 37 }

  condition:
    any of them
}
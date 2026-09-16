rule TTP_XOR_MULT_DOSStub_55dd {
  strings:
    $key_55dd = { 01 b5 [2] 75 ad [2] 32 af [2] 75 be [2] 3b b2 [2] 37 b8 [2] 20 b3 [2] 3b fd [2] 06 }

  condition:
    any of them
}
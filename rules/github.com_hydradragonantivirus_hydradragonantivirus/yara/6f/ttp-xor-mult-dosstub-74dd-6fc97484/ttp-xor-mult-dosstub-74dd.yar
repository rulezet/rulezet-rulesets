rule TTP_XOR_MULT_DOSStub_74dd {
  strings:
    $key_74dd = { 20 b5 [2] 54 ad [2] 13 af [2] 54 be [2] 1a b2 [2] 16 b8 [2] 01 b3 [2] 1a fd [2] 27 }

  condition:
    any of them
}
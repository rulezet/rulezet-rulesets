rule TTP_XOR_MULT_DOSStub_17dd {
  strings:
    $key_17dd = { 43 b5 [2] 37 ad [2] 70 af [2] 37 be [2] 79 b2 [2] 75 b8 [2] 62 b3 [2] 79 fd [2] 44 }

  condition:
    any of them
}
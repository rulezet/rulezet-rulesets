rule TTP_XOR_MULT_DOSStub_77dd {
  strings:
    $key_77dd = { 23 b5 [2] 57 ad [2] 10 af [2] 57 be [2] 19 b2 [2] 15 b8 [2] 02 b3 [2] 19 fd [2] 24 }

  condition:
    any of them
}
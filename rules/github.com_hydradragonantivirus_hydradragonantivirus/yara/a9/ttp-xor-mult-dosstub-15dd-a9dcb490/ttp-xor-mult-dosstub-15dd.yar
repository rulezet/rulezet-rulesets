rule TTP_XOR_MULT_DOSStub_15dd {
  strings:
    $key_15dd = { 41 b5 [2] 35 ad [2] 72 af [2] 35 be [2] 7b b2 [2] 77 b8 [2] 60 b3 [2] 7b fd [2] 46 }

  condition:
    any of them
}
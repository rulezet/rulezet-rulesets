rule TTP_XOR_MULT_DOSStub_79dd {
  strings:
    $key_79dd = { 2d b5 [2] 59 ad [2] 1e af [2] 59 be [2] 17 b2 [2] 1b b8 [2] 0c b3 [2] 17 fd [2] 2a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_59dd {
  strings:
    $key_59dd = { 0d b5 [2] 79 ad [2] 3e af [2] 79 be [2] 37 b2 [2] 3b b8 [2] 2c b3 [2] 37 fd [2] 0a }

  condition:
    any of them
}
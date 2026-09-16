rule TTP_XOR_MULT_DOSStub_d8dd {
  strings:
    $key_d8dd = { 8c b5 [2] f8 ad [2] bf af [2] f8 be [2] b6 b2 [2] ba b8 [2] ad b3 [2] b6 fd [2] 8b }

  condition:
    any of them
}
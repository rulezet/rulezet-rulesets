rule TTP_XOR_MULT_DOSStub_43dd {
  strings:
    $key_43dd = { 17 b5 [2] 63 ad [2] 24 af [2] 63 be [2] 2d b2 [2] 21 b8 [2] 36 b3 [2] 2d fd [2] 10 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_31dd {
  strings:
    $key_31dd = { 65 b5 [2] 11 ad [2] 56 af [2] 11 be [2] 5f b2 [2] 53 b8 [2] 44 b3 [2] 5f fd [2] 62 }

  condition:
    any of them
}
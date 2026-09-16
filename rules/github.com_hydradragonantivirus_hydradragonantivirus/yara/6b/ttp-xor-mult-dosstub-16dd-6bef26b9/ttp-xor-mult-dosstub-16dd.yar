rule TTP_XOR_MULT_DOSStub_16dd {
  strings:
    $key_16dd = { 42 b5 [2] 36 ad [2] 71 af [2] 36 be [2] 78 b2 [2] 74 b8 [2] 63 b3 [2] 78 fd [2] 45 }

  condition:
    any of them
}
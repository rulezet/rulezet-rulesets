rule TTP_XOR_MULT_DOSStub_60dd {
  strings:
    $key_60dd = { 34 b5 [2] 40 ad [2] 07 af [2] 40 be [2] 0e b2 [2] 02 b8 [2] 15 b3 [2] 0e fd [2] 33 }

  condition:
    any of them
}
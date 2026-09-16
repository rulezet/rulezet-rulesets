rule TTP_XOR_MULT_DOSStub_73dd {
  strings:
    $key_73dd = { 27 b5 [2] 53 ad [2] 14 af [2] 53 be [2] 1d b2 [2] 11 b8 [2] 06 b3 [2] 1d fd [2] 20 }

  condition:
    any of them
}
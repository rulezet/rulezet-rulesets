rule TTP_XOR_MULT_DOSStub_52dd {
  strings:
    $key_52dd = { 06 b5 [2] 72 ad [2] 35 af [2] 72 be [2] 3c b2 [2] 30 b8 [2] 27 b3 [2] 3c fd [2] 01 }

  condition:
    any of them
}
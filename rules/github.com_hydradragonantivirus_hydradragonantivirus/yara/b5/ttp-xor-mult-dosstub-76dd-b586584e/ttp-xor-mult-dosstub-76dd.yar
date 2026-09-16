rule TTP_XOR_MULT_DOSStub_76dd {
  strings:
    $key_76dd = { 22 b5 [2] 56 ad [2] 11 af [2] 56 be [2] 18 b2 [2] 14 b8 [2] 03 b3 [2] 18 fd [2] 25 }

  condition:
    any of them
}
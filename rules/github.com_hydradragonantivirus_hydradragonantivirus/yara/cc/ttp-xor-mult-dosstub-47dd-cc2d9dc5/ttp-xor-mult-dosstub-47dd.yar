rule TTP_XOR_MULT_DOSStub_47dd {
  strings:
    $key_47dd = { 13 b5 [2] 67 ad [2] 20 af [2] 67 be [2] 29 b2 [2] 25 b8 [2] 32 b3 [2] 29 fd [2] 14 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_27dd {
  strings:
    $key_27dd = { 73 b5 [2] 07 ad [2] 40 af [2] 07 be [2] 49 b2 [2] 45 b8 [2] 52 b3 [2] 49 fd [2] 74 }

  condition:
    any of them
}
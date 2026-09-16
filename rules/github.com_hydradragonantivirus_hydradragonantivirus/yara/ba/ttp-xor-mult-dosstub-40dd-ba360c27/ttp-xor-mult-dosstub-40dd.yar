rule TTP_XOR_MULT_DOSStub_40dd {
  strings:
    $key_40dd = { 14 b5 [2] 60 ad [2] 27 af [2] 60 be [2] 2e b2 [2] 22 b8 [2] 35 b3 [2] 2e fd [2] 13 }

  condition:
    any of them
}
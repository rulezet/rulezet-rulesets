rule TTP_XOR_MULT_DOSStub_cadd {
  strings:
    $key_cadd = { 9e b5 [2] ea ad [2] ad af [2] ea be [2] a4 b2 [2] a8 b8 [2] bf b3 [2] a4 fd [2] 99 }

  condition:
    any of them
}
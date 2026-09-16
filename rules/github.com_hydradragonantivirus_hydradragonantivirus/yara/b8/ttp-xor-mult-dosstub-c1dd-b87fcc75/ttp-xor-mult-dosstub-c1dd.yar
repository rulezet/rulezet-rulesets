rule TTP_XOR_MULT_DOSStub_c1dd {
  strings:
    $key_c1dd = { 95 b5 [2] e1 ad [2] a6 af [2] e1 be [2] af b2 [2] a3 b8 [2] b4 b3 [2] af fd [2] 92 }

  condition:
    any of them
}
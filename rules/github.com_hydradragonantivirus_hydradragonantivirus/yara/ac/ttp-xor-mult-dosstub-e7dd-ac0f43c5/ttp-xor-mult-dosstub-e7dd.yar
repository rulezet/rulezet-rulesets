rule TTP_XOR_MULT_DOSStub_e7dd {
  strings:
    $key_e7dd = { b3 b5 [2] c7 ad [2] 80 af [2] c7 be [2] 89 b2 [2] 85 b8 [2] 92 b3 [2] 89 fd [2] b4 }

  condition:
    any of them
}
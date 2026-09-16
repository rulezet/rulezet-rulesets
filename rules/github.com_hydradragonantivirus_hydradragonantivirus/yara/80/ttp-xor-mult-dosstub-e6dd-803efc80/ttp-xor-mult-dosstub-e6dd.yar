rule TTP_XOR_MULT_DOSStub_e6dd {
  strings:
    $key_e6dd = { b2 b5 [2] c6 ad [2] 81 af [2] c6 be [2] 88 b2 [2] 84 b8 [2] 93 b3 [2] 88 fd [2] b5 }

  condition:
    any of them
}
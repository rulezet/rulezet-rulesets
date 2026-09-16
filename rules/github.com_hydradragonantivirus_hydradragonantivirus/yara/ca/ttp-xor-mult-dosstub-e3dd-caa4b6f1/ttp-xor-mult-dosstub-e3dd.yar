rule TTP_XOR_MULT_DOSStub_e3dd {
  strings:
    $key_e3dd = { b7 b5 [2] c3 ad [2] 84 af [2] c3 be [2] 8d b2 [2] 81 b8 [2] 96 b3 [2] 8d fd [2] b0 }

  condition:
    any of them
}
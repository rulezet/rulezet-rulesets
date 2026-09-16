rule TTP_XOR_MULT_DOSStub_d5dd {
  strings:
    $key_d5dd = { 81 b5 [2] f5 ad [2] b2 af [2] f5 be [2] bb b2 [2] b7 b8 [2] a0 b3 [2] bb fd [2] 86 }

  condition:
    any of them
}
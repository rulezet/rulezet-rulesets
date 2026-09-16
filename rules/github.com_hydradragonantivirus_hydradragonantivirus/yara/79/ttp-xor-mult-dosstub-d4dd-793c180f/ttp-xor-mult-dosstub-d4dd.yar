rule TTP_XOR_MULT_DOSStub_d4dd {
  strings:
    $key_d4dd = { 80 b5 [2] f4 ad [2] b3 af [2] f4 be [2] ba b2 [2] b6 b8 [2] a1 b3 [2] ba fd [2] 87 }

  condition:
    any of them
}
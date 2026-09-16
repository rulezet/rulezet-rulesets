rule TTP_XOR_MULT_DOSStub_d0dd {
  strings:
    $key_d0dd = { 84 b5 [2] f0 ad [2] b7 af [2] f0 be [2] be b2 [2] b2 b8 [2] a5 b3 [2] be fd [2] 83 }

  condition:
    any of them
}
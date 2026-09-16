rule TTP_XOR_MULT_DOSStub_c5dd {
  strings:
    $key_c5dd = { 91 b5 [2] e5 ad [2] a2 af [2] e5 be [2] ab b2 [2] a7 b8 [2] b0 b3 [2] ab fd [2] 96 }

  condition:
    any of them
}
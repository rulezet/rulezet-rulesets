rule TTP_XOR_MULT_DOSStub_82dd {
  strings:
    $key_82dd = { d6 b5 [2] a2 ad [2] e5 af [2] a2 be [2] ec b2 [2] e0 b8 [2] f7 b3 [2] ec fd [2] d1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_92a2 {
  strings:
    $key_92a2 = { c6 ca [2] b2 d2 [2] f5 d0 [2] b2 c1 [2] fc cd [2] f0 c7 [2] e7 cc [2] fc 82 [2] c1 }

  condition:
    any of them
}
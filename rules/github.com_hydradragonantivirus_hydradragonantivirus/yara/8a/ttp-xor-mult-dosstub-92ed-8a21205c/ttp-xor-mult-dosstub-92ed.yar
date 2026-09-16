rule TTP_XOR_MULT_DOSStub_92ed {
  strings:
    $key_92ed = { c6 85 [2] b2 9d [2] f5 9f [2] b2 8e [2] fc 82 [2] f0 88 [2] e7 83 [2] fc cd [2] c1 }

  condition:
    any of them
}
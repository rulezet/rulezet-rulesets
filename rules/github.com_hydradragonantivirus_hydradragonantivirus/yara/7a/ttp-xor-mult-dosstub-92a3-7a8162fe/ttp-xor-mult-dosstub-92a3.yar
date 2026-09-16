rule TTP_XOR_MULT_DOSStub_92a3 {
  strings:
    $key_92a3 = { c6 cb [2] b2 d3 [2] f5 d1 [2] b2 c0 [2] fc cc [2] f0 c6 [2] e7 cd [2] fc 83 [2] c1 }

  condition:
    any of them
}
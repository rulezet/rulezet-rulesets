rule TTP_XOR_MULT_DOSStub_85a3 {
  strings:
    $key_85a3 = { d1 cb [2] a5 d3 [2] e2 d1 [2] a5 c0 [2] eb cc [2] e7 c6 [2] f0 cd [2] eb 83 [2] d6 }

  condition:
    any of them
}
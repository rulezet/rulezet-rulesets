rule TTP_XOR_MULT_DOSStub_93a1 {
  strings:
    $key_93a1 = { c7 c9 [2] b3 d1 [2] f4 d3 [2] b3 c2 [2] fd ce [2] f1 c4 [2] e6 cf [2] fd 81 [2] c0 }

  condition:
    any of them
}
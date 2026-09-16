rule TTP_XOR_MULT_DOSStub_97f3 {
  strings:
    $key_97f3 = { c3 9b [2] b7 83 [2] f0 81 [2] b7 90 [2] f9 9c [2] f5 96 [2] e2 9d [2] f9 d3 [2] c4 }

  condition:
    any of them
}
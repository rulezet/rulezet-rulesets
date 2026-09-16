rule TTP_XOR_MULT_DOSStub_92f3 {
  strings:
    $key_92f3 = { c6 9b [2] b2 83 [2] f5 81 [2] b2 90 [2] fc 9c [2] f0 96 [2] e7 9d [2] fc d3 [2] c1 }

  condition:
    any of them
}
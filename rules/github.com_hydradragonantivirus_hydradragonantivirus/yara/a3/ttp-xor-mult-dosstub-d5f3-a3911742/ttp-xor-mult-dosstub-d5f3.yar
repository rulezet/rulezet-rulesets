rule TTP_XOR_MULT_DOSStub_d5f3 {
  strings:
    $key_d5f3 = { 81 9b [2] f5 83 [2] b2 81 [2] f5 90 [2] bb 9c [2] b7 96 [2] a0 9d [2] bb d3 [2] 86 }

  condition:
    any of them
}
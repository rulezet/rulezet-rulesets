rule TTP_XOR_MULT_DOSStub_86f3 {
  strings:
    $key_86f3 = { d2 9b [2] a6 83 [2] e1 81 [2] a6 90 [2] e8 9c [2] e4 96 [2] f3 9d [2] e8 d3 [2] d5 }

  condition:
    any of them
}
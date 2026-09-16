rule TTP_XOR_MULT_DOSStub_94f3 {
  strings:
    $key_94f3 = { c0 9b [2] b4 83 [2] f3 81 [2] b4 90 [2] fa 9c [2] f6 96 [2] e1 9d [2] fa d3 [2] c7 }

  condition:
    any of them
}
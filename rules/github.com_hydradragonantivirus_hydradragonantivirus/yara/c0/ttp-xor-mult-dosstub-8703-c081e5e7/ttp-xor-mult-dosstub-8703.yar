rule TTP_XOR_MULT_DOSStub_8703 {
  strings:
    $key_8703 = { d3 6b [2] a7 73 [2] e0 71 [2] a7 60 [2] e9 6c [2] e5 66 [2] f2 6d [2] e9 23 [2] d4 }

  condition:
    any of them
}
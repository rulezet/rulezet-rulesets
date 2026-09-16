rule TTP_XOR_MULT_DOSStub_8708 {
  strings:
    $key_8708 = { d3 60 [2] a7 78 [2] e0 7a [2] a7 6b [2] e9 67 [2] e5 6d [2] f2 66 [2] e9 28 [2] d4 }

  condition:
    any of them
}
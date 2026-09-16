rule TTP_XOR_MULT_DOSStub_87e4 {
  strings:
    $key_87e4 = { d3 8c [2] a7 94 [2] e0 96 [2] a7 87 [2] e9 8b [2] e5 81 [2] f2 8a [2] e9 c4 [2] d4 }

  condition:
    any of them
}
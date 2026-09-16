rule TTP_XOR_MULT_DOSStub_8704 {
  strings:
    $key_8704 = { d3 6c [2] a7 74 [2] e0 76 [2] a7 67 [2] e9 6b [2] e5 61 [2] f2 6a [2] e9 24 [2] d4 }

  condition:
    any of them
}
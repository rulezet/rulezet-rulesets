rule TTP_XOR_MULT_DOSStub_8734 {
  strings:
    $key_8734 = { d3 5c [2] a7 44 [2] e0 46 [2] a7 57 [2] e9 5b [2] e5 51 [2] f2 5a [2] e9 14 [2] d4 }

  condition:
    any of them
}
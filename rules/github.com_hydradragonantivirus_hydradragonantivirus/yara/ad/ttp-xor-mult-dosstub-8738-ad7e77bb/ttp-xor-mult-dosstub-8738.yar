rule TTP_XOR_MULT_DOSStub_8738 {
  strings:
    $key_8738 = { d3 50 [2] a7 48 [2] e0 4a [2] a7 5b [2] e9 57 [2] e5 5d [2] f2 56 [2] e9 18 [2] d4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8715 {
  strings:
    $key_8715 = { d3 7d [2] a7 65 [2] e0 67 [2] a7 76 [2] e9 7a [2] e5 70 [2] f2 7b [2] e9 35 [2] d4 }

  condition:
    any of them
}
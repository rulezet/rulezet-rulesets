rule TTP_XOR_MULT_DOSStub_8705 {
  strings:
    $key_8705 = { d3 6d [2] a7 75 [2] e0 77 [2] a7 66 [2] e9 6a [2] e5 60 [2] f2 6b [2] e9 25 [2] d4 }

  condition:
    any of them
}
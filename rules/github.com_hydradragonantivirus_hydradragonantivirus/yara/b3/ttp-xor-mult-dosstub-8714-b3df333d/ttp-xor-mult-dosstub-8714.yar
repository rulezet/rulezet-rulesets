rule TTP_XOR_MULT_DOSStub_8714 {
  strings:
    $key_8714 = { d3 7c [2] a7 64 [2] e0 66 [2] a7 77 [2] e9 7b [2] e5 71 [2] f2 7a [2] e9 34 [2] d4 }

  condition:
    any of them
}
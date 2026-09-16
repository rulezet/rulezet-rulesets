rule TTP_XOR_MULT_DOSStub_8729 {
  strings:
    $key_8729 = { d3 41 [2] a7 59 [2] e0 5b [2] a7 4a [2] e9 46 [2] e5 4c [2] f2 47 [2] e9 09 [2] d4 }

  condition:
    any of them
}
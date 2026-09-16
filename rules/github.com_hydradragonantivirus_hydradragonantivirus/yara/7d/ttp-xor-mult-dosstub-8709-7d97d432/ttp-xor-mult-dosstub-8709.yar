rule TTP_XOR_MULT_DOSStub_8709 {
  strings:
    $key_8709 = { d3 61 [2] a7 79 [2] e0 7b [2] a7 6a [2] e9 66 [2] e5 6c [2] f2 67 [2] e9 29 [2] d4 }

  condition:
    any of them
}
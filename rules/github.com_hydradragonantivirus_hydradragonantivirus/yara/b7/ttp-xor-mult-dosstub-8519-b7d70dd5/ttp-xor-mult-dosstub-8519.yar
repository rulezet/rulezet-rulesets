rule TTP_XOR_MULT_DOSStub_8519 {
  strings:
    $key_8519 = { d1 71 [2] a5 69 [2] e2 6b [2] a5 7a [2] eb 76 [2] e7 7c [2] f0 77 [2] eb 39 [2] d6 }

  condition:
    any of them
}
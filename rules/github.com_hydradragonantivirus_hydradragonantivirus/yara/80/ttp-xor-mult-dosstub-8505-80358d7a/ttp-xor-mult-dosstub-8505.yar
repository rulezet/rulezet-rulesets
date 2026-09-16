rule TTP_XOR_MULT_DOSStub_8505 {
  strings:
    $key_8505 = { d1 6d [2] a5 75 [2] e2 77 [2] a5 66 [2] eb 6a [2] e7 60 [2] f0 6b [2] eb 25 [2] d6 }

  condition:
    any of them
}
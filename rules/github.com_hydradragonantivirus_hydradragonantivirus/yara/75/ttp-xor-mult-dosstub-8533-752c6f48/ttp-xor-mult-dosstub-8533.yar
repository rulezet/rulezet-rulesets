rule TTP_XOR_MULT_DOSStub_8533 {
  strings:
    $key_8533 = { d1 5b [2] a5 43 [2] e2 41 [2] a5 50 [2] eb 5c [2] e7 56 [2] f0 5d [2] eb 13 [2] d6 }

  condition:
    any of them
}
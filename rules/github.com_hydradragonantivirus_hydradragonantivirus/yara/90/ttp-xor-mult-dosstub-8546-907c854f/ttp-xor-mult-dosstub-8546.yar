rule TTP_XOR_MULT_DOSStub_8546 {
  strings:
    $key_8546 = { d1 2e [2] a5 36 [2] e2 34 [2] a5 25 [2] eb 29 [2] e7 23 [2] f0 28 [2] eb 66 [2] d6 }

  condition:
    any of them
}
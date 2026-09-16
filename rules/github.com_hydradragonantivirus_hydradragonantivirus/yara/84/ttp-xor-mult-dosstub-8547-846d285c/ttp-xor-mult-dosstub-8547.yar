rule TTP_XOR_MULT_DOSStub_8547 {
  strings:
    $key_8547 = { d1 2f [2] a5 37 [2] e2 35 [2] a5 24 [2] eb 28 [2] e7 22 [2] f0 29 [2] eb 67 [2] d6 }

  condition:
    any of them
}
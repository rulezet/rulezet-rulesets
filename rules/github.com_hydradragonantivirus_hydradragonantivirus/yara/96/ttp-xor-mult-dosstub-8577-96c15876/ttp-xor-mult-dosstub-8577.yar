rule TTP_XOR_MULT_DOSStub_8577 {
  strings:
    $key_8577 = { d1 1f [2] a5 07 [2] e2 05 [2] a5 14 [2] eb 18 [2] e7 12 [2] f0 19 [2] eb 57 [2] d6 }

  condition:
    any of them
}
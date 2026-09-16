rule TTP_XOR_MULT_DOSStub_8526 {
  strings:
    $key_8526 = { d1 4e [2] a5 56 [2] e2 54 [2] a5 45 [2] eb 49 [2] e7 43 [2] f0 48 [2] eb 06 [2] d6 }

  condition:
    any of them
}
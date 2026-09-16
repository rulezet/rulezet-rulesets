rule TTP_XOR_MULT_DOSStub_8520 {
  strings:
    $key_8520 = { d1 48 [2] a5 50 [2] e2 52 [2] a5 43 [2] eb 4f [2] e7 45 [2] f0 4e [2] eb 00 [2] d6 }

  condition:
    any of them
}
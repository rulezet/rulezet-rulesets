rule TTP_XOR_MULT_DOSStub_8531 {
  strings:
    $key_8531 = { d1 59 [2] a5 41 [2] e2 43 [2] a5 52 [2] eb 5e [2] e7 54 [2] f0 5f [2] eb 11 [2] d6 }

  condition:
    any of them
}
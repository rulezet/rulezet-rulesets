rule TTP_XOR_MULT_DOSStub_8530 {
  strings:
    $key_8530 = { d1 58 [2] a5 40 [2] e2 42 [2] a5 53 [2] eb 5f [2] e7 55 [2] f0 5e [2] eb 10 [2] d6 }

  condition:
    any of them
}
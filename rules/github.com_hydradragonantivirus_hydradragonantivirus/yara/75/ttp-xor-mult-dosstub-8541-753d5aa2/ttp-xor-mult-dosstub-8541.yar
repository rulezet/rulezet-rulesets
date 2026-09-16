rule TTP_XOR_MULT_DOSStub_8541 {
  strings:
    $key_8541 = { d1 29 [2] a5 31 [2] e2 33 [2] a5 22 [2] eb 2e [2] e7 24 [2] f0 2f [2] eb 61 [2] d6 }

  condition:
    any of them
}
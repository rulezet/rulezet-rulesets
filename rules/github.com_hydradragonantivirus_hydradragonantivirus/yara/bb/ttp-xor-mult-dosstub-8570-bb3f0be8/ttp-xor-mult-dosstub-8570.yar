rule TTP_XOR_MULT_DOSStub_8570 {
  strings:
    $key_8570 = { d1 18 [2] a5 00 [2] e2 02 [2] a5 13 [2] eb 1f [2] e7 15 [2] f0 1e [2] eb 50 [2] d6 }

  condition:
    any of them
}
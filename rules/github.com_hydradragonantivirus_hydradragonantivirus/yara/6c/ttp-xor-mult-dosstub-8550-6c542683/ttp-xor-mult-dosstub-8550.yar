rule TTP_XOR_MULT_DOSStub_8550 {
  strings:
    $key_8550 = { d1 38 [2] a5 20 [2] e2 22 [2] a5 33 [2] eb 3f [2] e7 35 [2] f0 3e [2] eb 70 [2] d6 }

  condition:
    any of them
}
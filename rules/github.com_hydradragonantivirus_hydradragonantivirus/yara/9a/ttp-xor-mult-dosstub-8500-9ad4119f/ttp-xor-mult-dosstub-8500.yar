rule TTP_XOR_MULT_DOSStub_8500 {
  strings:
    $key_8500 = { d1 68 [2] a5 70 [2] e2 72 [2] a5 63 [2] eb 6f [2] e7 65 [2] f0 6e [2] eb 20 [2] d6 }

  condition:
    any of them
}
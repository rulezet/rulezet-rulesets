rule TTP_XOR_MULT_DOSStub_8571 {
  strings:
    $key_8571 = { d1 19 [2] a5 01 [2] e2 03 [2] a5 12 [2] eb 1e [2] e7 14 [2] f0 1f [2] eb 51 [2] d6 }

  condition:
    any of them
}
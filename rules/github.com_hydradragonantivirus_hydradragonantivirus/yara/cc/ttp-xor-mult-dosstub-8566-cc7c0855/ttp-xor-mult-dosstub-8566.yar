rule TTP_XOR_MULT_DOSStub_8566 {
  strings:
    $key_8566 = { d1 0e [2] a5 16 [2] e2 14 [2] a5 05 [2] eb 09 [2] e7 03 [2] f0 08 [2] eb 46 [2] d6 }

  condition:
    any of them
}
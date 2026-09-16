rule TTP_XOR_MULT_DOSStub_8561 {
  strings:
    $key_8561 = { d1 09 [2] a5 11 [2] e2 13 [2] a5 02 [2] eb 0e [2] e7 04 [2] f0 0f [2] eb 41 [2] d6 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8568 {
  strings:
    $key_8568 = { d1 00 [2] a5 18 [2] e2 1a [2] a5 0b [2] eb 07 [2] e7 0d [2] f0 06 [2] eb 48 [2] d6 }

  condition:
    any of them
}
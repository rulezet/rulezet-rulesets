rule TTP_XOR_MULT_DOSStub_8525 {
  strings:
    $key_8525 = { d1 4d [2] a5 55 [2] e2 57 [2] a5 46 [2] eb 4a [2] e7 40 [2] f0 4b [2] eb 05 [2] d6 }

  condition:
    any of them
}
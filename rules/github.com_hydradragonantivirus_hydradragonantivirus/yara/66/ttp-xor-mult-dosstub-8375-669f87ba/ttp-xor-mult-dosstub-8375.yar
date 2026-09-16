rule TTP_XOR_MULT_DOSStub_8375 {
  strings:
    $key_8375 = { d7 1d [2] a3 05 [2] e4 07 [2] a3 16 [2] ed 1a [2] e1 10 [2] f6 1b [2] ed 55 [2] d0 }

  condition:
    any of them
}
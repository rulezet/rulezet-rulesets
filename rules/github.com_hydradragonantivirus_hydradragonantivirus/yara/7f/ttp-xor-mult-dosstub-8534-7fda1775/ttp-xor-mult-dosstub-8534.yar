rule TTP_XOR_MULT_DOSStub_8534 {
  strings:
    $key_8534 = { d1 5c [2] a5 44 [2] e2 46 [2] a5 57 [2] eb 5b [2] e7 51 [2] f0 5a [2] eb 14 [2] d6 }

  condition:
    any of them
}
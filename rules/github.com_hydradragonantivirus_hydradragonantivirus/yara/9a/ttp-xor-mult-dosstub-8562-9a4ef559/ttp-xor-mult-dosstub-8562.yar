rule TTP_XOR_MULT_DOSStub_8562 {
  strings:
    $key_8562 = { d1 0a [2] a5 12 [2] e2 10 [2] a5 01 [2] eb 0d [2] e7 07 [2] f0 0c [2] eb 42 [2] d6 }

  condition:
    any of them
}
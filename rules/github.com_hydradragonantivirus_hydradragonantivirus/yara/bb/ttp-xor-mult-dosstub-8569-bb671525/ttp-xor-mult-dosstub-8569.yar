rule TTP_XOR_MULT_DOSStub_8569 {
  strings:
    $key_8569 = { d1 01 [2] a5 19 [2] e2 1b [2] a5 0a [2] eb 06 [2] e7 0c [2] f0 07 [2] eb 49 [2] d6 }

  condition:
    any of them
}
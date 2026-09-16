rule TTP_XOR_MULT_DOSStub_83e4 {
  strings:
    $key_83e4 = { d7 8c [2] a3 94 [2] e4 96 [2] a3 87 [2] ed 8b [2] e1 81 [2] f6 8a [2] ed c4 [2] d0 }

  condition:
    any of them
}
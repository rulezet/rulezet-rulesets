rule TTP_XOR_MULT_DOSStub_83f5 {
  strings:
    $key_83f5 = { d7 9d [2] a3 85 [2] e4 87 [2] a3 96 [2] ed 9a [2] e1 90 [2] f6 9b [2] ed d5 [2] d0 }

  condition:
    any of them
}
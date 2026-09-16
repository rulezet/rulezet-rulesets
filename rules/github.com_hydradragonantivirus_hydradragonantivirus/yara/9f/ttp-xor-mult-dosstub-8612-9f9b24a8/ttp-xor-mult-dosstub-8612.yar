rule TTP_XOR_MULT_DOSStub_8612 {
  strings:
    $key_8612 = { d2 7a [2] a6 62 [2] e1 60 [2] a6 71 [2] e8 7d [2] e4 77 [2] f3 7c [2] e8 32 [2] d5 }

  condition:
    any of them
}
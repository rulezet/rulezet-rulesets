rule TTP_XOR_MULT_DOSStub_90e4 {
  strings:
    $key_90e4 = { c4 8c [2] b0 94 [2] f7 96 [2] b0 87 [2] fe 8b [2] f2 81 [2] e5 8a [2] fe c4 [2] c3 }

  condition:
    any of them
}
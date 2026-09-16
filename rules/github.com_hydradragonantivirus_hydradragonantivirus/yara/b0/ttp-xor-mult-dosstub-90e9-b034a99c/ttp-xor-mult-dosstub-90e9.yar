rule TTP_XOR_MULT_DOSStub_90e9 {
  strings:
    $key_90e9 = { c4 81 [2] b0 99 [2] f7 9b [2] b0 8a [2] fe 86 [2] f2 8c [2] e5 87 [2] fe c9 [2] c3 }

  condition:
    any of them
}
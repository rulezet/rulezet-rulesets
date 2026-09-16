rule TTP_XOR_MULT_DOSStub_9004 {
  strings:
    $key_9004 = { c4 6c [2] b0 74 [2] f7 76 [2] b0 67 [2] fe 6b [2] f2 61 [2] e5 6a [2] fe 24 [2] c3 }

  condition:
    any of them
}
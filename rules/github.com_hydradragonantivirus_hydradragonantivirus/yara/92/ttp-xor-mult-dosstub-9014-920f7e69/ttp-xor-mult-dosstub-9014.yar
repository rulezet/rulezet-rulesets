rule TTP_XOR_MULT_DOSStub_9014 {
  strings:
    $key_9014 = { c4 7c [2] b0 64 [2] f7 66 [2] b0 77 [2] fe 7b [2] f2 71 [2] e5 7a [2] fe 34 [2] c3 }

  condition:
    any of them
}
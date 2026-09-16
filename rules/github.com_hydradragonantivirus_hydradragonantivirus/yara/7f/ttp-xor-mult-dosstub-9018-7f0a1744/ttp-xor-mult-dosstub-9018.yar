rule TTP_XOR_MULT_DOSStub_9018 {
  strings:
    $key_9018 = { c4 70 [2] b0 68 [2] f7 6a [2] b0 7b [2] fe 77 [2] f2 7d [2] e5 76 [2] fe 38 [2] c3 }

  condition:
    any of them
}
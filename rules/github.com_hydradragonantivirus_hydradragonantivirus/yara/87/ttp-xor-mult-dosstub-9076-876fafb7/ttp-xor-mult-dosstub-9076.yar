rule TTP_XOR_MULT_DOSStub_9076 {
  strings:
    $key_9076 = { c4 1e [2] b0 06 [2] f7 04 [2] b0 15 [2] fe 19 [2] f2 13 [2] e5 18 [2] fe 56 [2] c3 }

  condition:
    any of them
}
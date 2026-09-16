rule TTP_XOR_MULT_DOSStub_9001 {
  strings:
    $key_9001 = { c4 69 [2] b0 71 [2] f7 73 [2] b0 62 [2] fe 6e [2] f2 64 [2] e5 6f [2] fe 21 [2] c3 }

  condition:
    any of them
}
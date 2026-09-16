rule TTP_XOR_MULT_DOSStub_9701 {
  strings:
    $key_9701 = { c3 69 [2] b7 71 [2] f0 73 [2] b7 62 [2] f9 6e [2] f5 64 [2] e2 6f [2] f9 21 [2] c4 }

  condition:
    any of them
}
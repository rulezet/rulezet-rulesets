rule TTP_XOR_MULT_DOSStub_9706 {
  strings:
    $key_9706 = { c3 6e [2] b7 76 [2] f0 74 [2] b7 65 [2] f9 69 [2] f5 63 [2] e2 68 [2] f9 26 [2] c4 }

  condition:
    any of them
}
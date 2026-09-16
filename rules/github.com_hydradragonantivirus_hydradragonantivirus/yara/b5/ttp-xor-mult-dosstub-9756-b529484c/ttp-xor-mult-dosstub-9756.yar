rule TTP_XOR_MULT_DOSStub_9756 {
  strings:
    $key_9756 = { c3 3e [2] b7 26 [2] f0 24 [2] b7 35 [2] f9 39 [2] f5 33 [2] e2 38 [2] f9 76 [2] c4 }

  condition:
    any of them
}
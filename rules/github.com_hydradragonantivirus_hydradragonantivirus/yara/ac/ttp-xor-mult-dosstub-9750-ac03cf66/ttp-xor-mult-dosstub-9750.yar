rule TTP_XOR_MULT_DOSStub_9750 {
  strings:
    $key_9750 = { c3 38 [2] b7 20 [2] f0 22 [2] b7 33 [2] f9 3f [2] f5 35 [2] e2 3e [2] f9 70 [2] c4 }

  condition:
    any of them
}
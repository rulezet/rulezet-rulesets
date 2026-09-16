rule TTP_XOR_MULT_DOSStub_9747 {
  strings:
    $key_9747 = { c3 2f [2] b7 37 [2] f0 35 [2] b7 24 [2] f9 28 [2] f5 22 [2] e2 29 [2] f9 67 [2] c4 }

  condition:
    any of them
}
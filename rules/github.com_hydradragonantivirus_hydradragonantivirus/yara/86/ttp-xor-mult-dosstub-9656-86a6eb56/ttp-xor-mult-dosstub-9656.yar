rule TTP_XOR_MULT_DOSStub_9656 {
  strings:
    $key_9656 = { c2 3e [2] b6 26 [2] f1 24 [2] b6 35 [2] f8 39 [2] f4 33 [2] e3 38 [2] f8 76 [2] c5 }

  condition:
    any of them
}
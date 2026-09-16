rule TTP_XOR_MULT_DOSStub_9716 {
  strings:
    $key_9716 = { c3 7e [2] b7 66 [2] f0 64 [2] b7 75 [2] f9 79 [2] f5 73 [2] e2 78 [2] f9 36 [2] c4 }

  condition:
    any of them
}
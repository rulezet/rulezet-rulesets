rule TTP_XOR_MULT_DOSStub_9016 {
  strings:
    $key_9016 = { c4 7e [2] b0 66 [2] f7 64 [2] b0 75 [2] fe 79 [2] f2 73 [2] e5 78 [2] fe 36 [2] c3 }

  condition:
    any of them
}
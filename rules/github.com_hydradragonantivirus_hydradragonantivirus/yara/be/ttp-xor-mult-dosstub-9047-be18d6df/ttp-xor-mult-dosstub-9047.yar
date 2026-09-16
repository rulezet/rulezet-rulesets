rule TTP_XOR_MULT_DOSStub_9047 {
  strings:
    $key_9047 = { c4 2f [2] b0 37 [2] f7 35 [2] b0 24 [2] fe 28 [2] f2 22 [2] e5 29 [2] fe 67 [2] c3 }

  condition:
    any of them
}
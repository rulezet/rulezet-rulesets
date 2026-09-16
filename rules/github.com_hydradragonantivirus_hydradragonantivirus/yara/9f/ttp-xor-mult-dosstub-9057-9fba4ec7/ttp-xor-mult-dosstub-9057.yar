rule TTP_XOR_MULT_DOSStub_9057 {
  strings:
    $key_9057 = { c4 3f [2] b0 27 [2] f7 25 [2] b0 34 [2] fe 38 [2] f2 32 [2] e5 39 [2] fe 77 [2] c3 }

  condition:
    any of them
}
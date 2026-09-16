rule TTP_XOR_MULT_DOSStub_9670 {
  strings:
    $key_9670 = { c2 18 [2] b6 00 [2] f1 02 [2] b6 13 [2] f8 1f [2] f4 15 [2] e3 1e [2] f8 50 [2] c5 }

  condition:
    any of them
}
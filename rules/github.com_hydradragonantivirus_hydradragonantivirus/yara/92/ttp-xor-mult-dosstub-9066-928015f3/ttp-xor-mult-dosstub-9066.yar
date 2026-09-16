rule TTP_XOR_MULT_DOSStub_9066 {
  strings:
    $key_9066 = { c4 0e [2] b0 16 [2] f7 14 [2] b0 05 [2] fe 09 [2] f2 03 [2] e5 08 [2] fe 46 [2] c3 }

  condition:
    any of them
}
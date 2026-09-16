rule TTP_XOR_MULT_DOSStub_9006 {
  strings:
    $key_9006 = { c4 6e [2] b0 76 [2] f7 74 [2] b0 65 [2] fe 69 [2] f2 63 [2] e5 68 [2] fe 26 [2] c3 }

  condition:
    any of them
}
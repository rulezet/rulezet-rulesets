rule TTP_XOR_MULT_DOSStub_9011 {
  strings:
    $key_9011 = { c4 79 [2] b0 61 [2] f7 63 [2] b0 72 [2] fe 7e [2] f2 74 [2] e5 7f [2] fe 31 [2] c3 }

  condition:
    any of them
}
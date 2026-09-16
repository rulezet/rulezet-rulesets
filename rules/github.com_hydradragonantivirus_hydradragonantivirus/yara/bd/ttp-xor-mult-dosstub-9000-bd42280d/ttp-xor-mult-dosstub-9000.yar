rule TTP_XOR_MULT_DOSStub_9000 {
  strings:
    $key_9000 = { c4 68 [2] b0 70 [2] f7 72 [2] b0 63 [2] fe 6f [2] f2 65 [2] e5 6e [2] fe 20 [2] c3 }

  condition:
    any of them
}
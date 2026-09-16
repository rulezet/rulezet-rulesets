rule TTP_XOR_MULT_DOSStub_9015 {
  strings:
    $key_9015 = { c4 7d [2] b0 65 [2] f7 67 [2] b0 76 [2] fe 7a [2] f2 70 [2] e5 7b [2] fe 35 [2] c3 }

  condition:
    any of them
}
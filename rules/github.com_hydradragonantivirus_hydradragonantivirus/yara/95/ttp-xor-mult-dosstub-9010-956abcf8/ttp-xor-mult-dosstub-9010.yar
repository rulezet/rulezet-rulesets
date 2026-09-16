rule TTP_XOR_MULT_DOSStub_9010 {
  strings:
    $key_9010 = { c4 78 [2] b0 60 [2] f7 62 [2] b0 73 [2] fe 7f [2] f2 75 [2] e5 7e [2] fe 30 [2] c3 }

  condition:
    any of them
}
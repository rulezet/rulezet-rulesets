rule TTP_XOR_MULT_DOSStub_9061 {
  strings:
    $key_9061 = { c4 09 [2] b0 11 [2] f7 13 [2] b0 02 [2] fe 0e [2] f2 04 [2] e5 0f [2] fe 41 [2] c3 }

  condition:
    any of them
}
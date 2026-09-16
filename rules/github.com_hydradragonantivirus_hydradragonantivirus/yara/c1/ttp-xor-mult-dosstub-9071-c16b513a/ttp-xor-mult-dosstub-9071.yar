rule TTP_XOR_MULT_DOSStub_9071 {
  strings:
    $key_9071 = { c4 19 [2] b0 01 [2] f7 03 [2] b0 12 [2] fe 1e [2] f2 14 [2] e5 1f [2] fe 51 [2] c3 }

  condition:
    any of them
}
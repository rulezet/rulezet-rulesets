rule TTP_XOR_MULT_DOSStub_907c {
  strings:
    $key_907c = { c4 14 [2] b0 0c [2] f7 0e [2] b0 1f [2] fe 13 [2] f2 19 [2] e5 12 [2] fe 5c [2] c3 }

  condition:
    any of them
}
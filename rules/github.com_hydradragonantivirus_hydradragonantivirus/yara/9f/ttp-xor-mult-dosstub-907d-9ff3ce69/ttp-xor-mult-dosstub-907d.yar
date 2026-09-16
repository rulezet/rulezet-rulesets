rule TTP_XOR_MULT_DOSStub_907d {
  strings:
    $key_907d = { c4 15 [2] b0 0d [2] f7 0f [2] b0 1e [2] fe 12 [2] f2 18 [2] e5 13 [2] fe 5d [2] c3 }

  condition:
    any of them
}
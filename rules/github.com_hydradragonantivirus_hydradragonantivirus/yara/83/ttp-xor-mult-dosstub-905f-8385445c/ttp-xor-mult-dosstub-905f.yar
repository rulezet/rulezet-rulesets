rule TTP_XOR_MULT_DOSStub_905f {
  strings:
    $key_905f = { c4 37 [2] b0 2f [2] f7 2d [2] b0 3c [2] fe 30 [2] f2 3a [2] e5 31 [2] fe 7f [2] c3 }

  condition:
    any of them
}
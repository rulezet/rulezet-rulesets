rule TTP_XOR_MULT_DOSStub_904f {
  strings:
    $key_904f = { c4 27 [2] b0 3f [2] f7 3d [2] b0 2c [2] fe 20 [2] f2 2a [2] e5 21 [2] fe 6f [2] c3 }

  condition:
    any of them
}
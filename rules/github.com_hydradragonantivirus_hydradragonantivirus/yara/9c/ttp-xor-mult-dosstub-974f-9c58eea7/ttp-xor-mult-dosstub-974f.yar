rule TTP_XOR_MULT_DOSStub_974f {
  strings:
    $key_974f = { c3 27 [2] b7 3f [2] f0 3d [2] b7 2c [2] f9 20 [2] f5 2a [2] e2 21 [2] f9 6f [2] c4 }

  condition:
    any of them
}
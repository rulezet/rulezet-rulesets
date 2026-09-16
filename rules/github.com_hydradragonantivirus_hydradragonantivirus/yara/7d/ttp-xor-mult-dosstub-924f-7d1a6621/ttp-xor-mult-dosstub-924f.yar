rule TTP_XOR_MULT_DOSStub_924f {
  strings:
    $key_924f = { c6 27 [2] b2 3f [2] f5 3d [2] b2 2c [2] fc 20 [2] f0 2a [2] e7 21 [2] fc 6f [2] c1 }

  condition:
    any of them
}
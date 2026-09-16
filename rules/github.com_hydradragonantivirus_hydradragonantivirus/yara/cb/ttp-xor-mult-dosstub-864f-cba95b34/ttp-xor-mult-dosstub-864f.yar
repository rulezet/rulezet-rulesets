rule TTP_XOR_MULT_DOSStub_864f {
  strings:
    $key_864f = { d2 27 [2] a6 3f [2] e1 3d [2] a6 2c [2] e8 20 [2] e4 2a [2] f3 21 [2] e8 6f [2] d5 }

  condition:
    any of them
}
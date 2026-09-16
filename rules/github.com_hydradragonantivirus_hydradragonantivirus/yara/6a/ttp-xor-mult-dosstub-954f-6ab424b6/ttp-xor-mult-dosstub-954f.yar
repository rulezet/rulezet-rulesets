rule TTP_XOR_MULT_DOSStub_954f {
  strings:
    $key_954f = { c1 27 [2] b5 3f [2] f2 3d [2] b5 2c [2] fb 20 [2] f7 2a [2] e0 21 [2] fb 6f [2] c6 }

  condition:
    any of them
}
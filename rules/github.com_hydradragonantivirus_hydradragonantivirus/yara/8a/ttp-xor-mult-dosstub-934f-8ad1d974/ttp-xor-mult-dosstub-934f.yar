rule TTP_XOR_MULT_DOSStub_934f {
  strings:
    $key_934f = { c7 27 [2] b3 3f [2] f4 3d [2] b3 2c [2] fd 20 [2] f1 2a [2] e6 21 [2] fd 6f [2] c0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_944f {
  strings:
    $key_944f = { c0 27 [2] b4 3f [2] f3 3d [2] b4 2c [2] fa 20 [2] f6 2a [2] e1 21 [2] fa 6f [2] c7 }

  condition:
    any of them
}
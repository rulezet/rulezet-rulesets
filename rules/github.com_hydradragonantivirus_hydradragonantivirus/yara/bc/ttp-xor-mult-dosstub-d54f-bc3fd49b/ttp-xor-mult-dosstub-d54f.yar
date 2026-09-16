rule TTP_XOR_MULT_DOSStub_d54f {
  strings:
    $key_d54f = { 81 27 [2] f5 3f [2] b2 3d [2] f5 2c [2] bb 20 [2] b7 2a [2] a0 21 [2] bb 6f [2] 86 }

  condition:
    any of them
}
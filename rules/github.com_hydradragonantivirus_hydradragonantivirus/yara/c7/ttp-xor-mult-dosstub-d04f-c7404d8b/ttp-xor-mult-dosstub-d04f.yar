rule TTP_XOR_MULT_DOSStub_d04f {
  strings:
    $key_d04f = { 84 27 [2] f0 3f [2] b7 3d [2] f0 2c [2] be 20 [2] b2 2a [2] a5 21 [2] be 6f [2] 83 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_d84f {
  strings:
    $key_d84f = { 8c 27 [2] f8 3f [2] bf 3d [2] f8 2c [2] b6 20 [2] ba 2a [2] ad 21 [2] b6 6f [2] 8b }

  condition:
    any of them
}
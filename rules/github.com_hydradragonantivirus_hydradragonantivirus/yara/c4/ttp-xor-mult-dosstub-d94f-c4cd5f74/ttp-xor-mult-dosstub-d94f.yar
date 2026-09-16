rule TTP_XOR_MULT_DOSStub_d94f {
  strings:
    $key_d94f = { 8d 27 [2] f9 3f [2] be 3d [2] f9 2c [2] b7 20 [2] bb 2a [2] ac 21 [2] b7 6f [2] 8a }

  condition:
    any of them
}
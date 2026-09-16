rule TTP_XOR_MULT_DOSStub_d942 {
  strings:
    $key_d942 = { 8d 2a [2] f9 32 [2] be 30 [2] f9 21 [2] b7 2d [2] bb 27 [2] ac 2c [2] b7 62 [2] 8a }

  condition:
    any of them
}
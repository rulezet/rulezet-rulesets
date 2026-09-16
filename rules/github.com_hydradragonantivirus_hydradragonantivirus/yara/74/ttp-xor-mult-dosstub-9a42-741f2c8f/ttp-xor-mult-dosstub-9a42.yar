rule TTP_XOR_MULT_DOSStub_9a42 {
  strings:
    $key_9a42 = { ce 2a [2] ba 32 [2] fd 30 [2] ba 21 [2] f4 2d [2] f8 27 [2] ef 2c [2] f4 62 [2] c9 }

  condition:
    any of them
}
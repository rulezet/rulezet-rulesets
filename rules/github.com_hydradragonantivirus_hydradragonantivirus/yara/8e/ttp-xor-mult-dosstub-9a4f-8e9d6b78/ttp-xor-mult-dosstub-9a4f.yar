rule TTP_XOR_MULT_DOSStub_9a4f {
  strings:
    $key_9a4f = { ce 27 [2] ba 3f [2] fd 3d [2] ba 2c [2] f4 20 [2] f8 2a [2] ef 21 [2] f4 6f [2] c9 }

  condition:
    any of them
}
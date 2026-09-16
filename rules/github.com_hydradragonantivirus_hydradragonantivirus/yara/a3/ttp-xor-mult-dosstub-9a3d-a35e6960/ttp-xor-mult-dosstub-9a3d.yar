rule TTP_XOR_MULT_DOSStub_9a3d {
  strings:
    $key_9a3d = { ce 55 [2] ba 4d [2] fd 4f [2] ba 5e [2] f4 52 [2] f8 58 [2] ef 53 [2] f4 1d [2] c9 }

  condition:
    any of them
}
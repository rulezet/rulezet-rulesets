rule TTP_XOR_MULT_DOSStub_9a5f {
  strings:
    $key_9a5f = { ce 37 [2] ba 2f [2] fd 2d [2] ba 3c [2] f4 30 [2] f8 3a [2] ef 31 [2] f4 7f [2] c9 }

  condition:
    any of them
}
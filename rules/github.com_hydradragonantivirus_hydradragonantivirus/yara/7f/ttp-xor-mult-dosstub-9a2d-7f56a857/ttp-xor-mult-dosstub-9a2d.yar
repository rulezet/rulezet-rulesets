rule TTP_XOR_MULT_DOSStub_9a2d {
  strings:
    $key_9a2d = { ce 45 [2] ba 5d [2] fd 5f [2] ba 4e [2] f4 42 [2] f8 48 [2] ef 43 [2] f4 0d [2] c9 }

  condition:
    any of them
}
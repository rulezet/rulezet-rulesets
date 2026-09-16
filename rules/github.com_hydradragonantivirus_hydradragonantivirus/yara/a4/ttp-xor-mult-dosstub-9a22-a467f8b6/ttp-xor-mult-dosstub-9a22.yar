rule TTP_XOR_MULT_DOSStub_9a22 {
  strings:
    $key_9a22 = { ce 4a [2] ba 52 [2] fd 50 [2] ba 41 [2] f4 4d [2] f8 47 [2] ef 4c [2] f4 02 [2] c9 }

  condition:
    any of them
}
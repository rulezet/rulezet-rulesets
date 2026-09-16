rule TTP_XOR_MULT_DOSStub_9af2 {
  strings:
    $key_9af2 = { ce 9a [2] ba 82 [2] fd 80 [2] ba 91 [2] f4 9d [2] f8 97 [2] ef 9c [2] f4 d2 [2] c9 }

  condition:
    any of them
}
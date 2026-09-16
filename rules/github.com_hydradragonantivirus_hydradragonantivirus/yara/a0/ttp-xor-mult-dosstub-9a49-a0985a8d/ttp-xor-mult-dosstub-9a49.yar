rule TTP_XOR_MULT_DOSStub_9a49 {
  strings:
    $key_9a49 = { ce 21 [2] ba 39 [2] fd 3b [2] ba 2a [2] f4 26 [2] f8 2c [2] ef 27 [2] f4 69 [2] c9 }

  condition:
    any of them
}
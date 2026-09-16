rule TTP_XOR_MULT_DOSStub_9a54 {
  strings:
    $key_9a54 = { ce 3c [2] ba 24 [2] fd 26 [2] ba 37 [2] f4 3b [2] f8 31 [2] ef 3a [2] f4 74 [2] c9 }

  condition:
    any of them
}
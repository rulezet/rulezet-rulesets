rule TTP_XOR_MULT_DOSStub_9a1a {
  strings:
    $key_9a1a = { ce 72 [2] ba 6a [2] fd 68 [2] ba 79 [2] f4 75 [2] f8 7f [2] ef 74 [2] f4 3a [2] c9 }

  condition:
    any of them
}
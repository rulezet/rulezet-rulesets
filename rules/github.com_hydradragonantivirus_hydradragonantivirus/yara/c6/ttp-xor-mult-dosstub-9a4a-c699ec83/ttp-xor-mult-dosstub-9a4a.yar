rule TTP_XOR_MULT_DOSStub_9a4a {
  strings:
    $key_9a4a = { ce 22 [2] ba 3a [2] fd 38 [2] ba 29 [2] f4 25 [2] f8 2f [2] ef 24 [2] f4 6a [2] c9 }

  condition:
    any of them
}
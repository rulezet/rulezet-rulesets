rule TTP_XOR_MULT_DOSStub_9af8 {
  strings:
    $key_9af8 = { ce 90 [2] ba 88 [2] fd 8a [2] ba 9b [2] f4 97 [2] f8 9d [2] ef 96 [2] f4 d8 [2] c9 }

  condition:
    any of them
}
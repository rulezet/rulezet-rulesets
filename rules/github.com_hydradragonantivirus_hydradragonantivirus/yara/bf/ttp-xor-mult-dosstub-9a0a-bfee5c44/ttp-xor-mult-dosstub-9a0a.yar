rule TTP_XOR_MULT_DOSStub_9a0a {
  strings:
    $key_9a0a = { ce 62 [2] ba 7a [2] fd 78 [2] ba 69 [2] f4 65 [2] f8 6f [2] ef 64 [2] f4 2a [2] c9 }

  condition:
    any of them
}
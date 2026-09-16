rule TTP_XOR_MULT_DOSStub_9af1 {
  strings:
    $key_9af1 = { ce 99 [2] ba 81 [2] fd 83 [2] ba 92 [2] f4 9e [2] f8 94 [2] ef 9f [2] f4 d1 [2] c9 }

  condition:
    any of them
}
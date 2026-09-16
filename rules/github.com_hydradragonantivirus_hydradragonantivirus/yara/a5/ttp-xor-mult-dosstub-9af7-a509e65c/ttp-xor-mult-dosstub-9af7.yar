rule TTP_XOR_MULT_DOSStub_9af7 {
  strings:
    $key_9af7 = { ce 9f [2] ba 87 [2] fd 85 [2] ba 94 [2] f4 98 [2] f8 92 [2] ef 99 [2] f4 d7 [2] c9 }

  condition:
    any of them
}
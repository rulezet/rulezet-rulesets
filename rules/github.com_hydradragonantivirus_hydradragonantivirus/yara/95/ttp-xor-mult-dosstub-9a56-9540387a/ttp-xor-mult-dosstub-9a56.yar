rule TTP_XOR_MULT_DOSStub_9a56 {
  strings:
    $key_9a56 = { ce 3e [2] ba 26 [2] fd 24 [2] ba 35 [2] f4 39 [2] f8 33 [2] ef 38 [2] f4 76 [2] c9 }

  condition:
    any of them
}
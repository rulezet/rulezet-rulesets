rule TTP_XOR_MULT_DOSStub_9a44 {
  strings:
    $key_9a44 = { ce 2c [2] ba 34 [2] fd 36 [2] ba 27 [2] f4 2b [2] f8 21 [2] ef 2a [2] f4 64 [2] c9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9a79 {
  strings:
    $key_9a79 = { ce 11 [2] ba 09 [2] fd 0b [2] ba 1a [2] f4 16 [2] f8 1c [2] ef 17 [2] f4 59 [2] c9 }

  condition:
    any of them
}
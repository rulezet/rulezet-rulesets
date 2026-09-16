rule TTP_XOR_MULT_DOSStub_9a63 {
  strings:
    $key_9a63 = { ce 0b [2] ba 13 [2] fd 11 [2] ba 00 [2] f4 0c [2] f8 06 [2] ef 0d [2] f4 43 [2] c9 }

  condition:
    any of them
}
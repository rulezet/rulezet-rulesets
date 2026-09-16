rule TTP_XOR_MULT_DOSStub_9aee {
  strings:
    $key_9aee = { ce 86 [2] ba 9e [2] fd 9c [2] ba 8d [2] f4 81 [2] f8 8b [2] ef 80 [2] f4 ce [2] c9 }

  condition:
    any of them
}
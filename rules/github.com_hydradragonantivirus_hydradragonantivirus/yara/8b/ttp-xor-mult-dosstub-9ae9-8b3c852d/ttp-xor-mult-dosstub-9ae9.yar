rule TTP_XOR_MULT_DOSStub_9ae9 {
  strings:
    $key_9ae9 = { ce 81 [2] ba 99 [2] fd 9b [2] ba 8a [2] f4 86 [2] f8 8c [2] ef 87 [2] f4 c9 [2] c9 }

  condition:
    any of them
}
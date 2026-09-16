rule TTP_XOR_MULT_DOSStub_9a09 {
  strings:
    $key_9a09 = { ce 61 [2] ba 79 [2] fd 7b [2] ba 6a [2] f4 66 [2] f8 6c [2] ef 67 [2] f4 29 [2] c9 }

  condition:
    any of them
}
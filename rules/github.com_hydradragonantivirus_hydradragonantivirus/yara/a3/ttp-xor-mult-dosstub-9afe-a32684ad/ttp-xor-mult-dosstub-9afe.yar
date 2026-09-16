rule TTP_XOR_MULT_DOSStub_9afe {
  strings:
    $key_9afe = { ce 96 [2] ba 8e [2] fd 8c [2] ba 9d [2] f4 91 [2] f8 9b [2] ef 90 [2] f4 de [2] c9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_9a1c {
  strings:
    $key_9a1c = { ce 74 [2] ba 6c [2] fd 6e [2] ba 7f [2] f4 73 [2] f8 79 [2] ef 72 [2] f4 3c [2] c9 }

  condition:
    any of them
}